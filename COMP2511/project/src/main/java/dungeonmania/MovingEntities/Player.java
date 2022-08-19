package dungeonmania.MovingEntities;

import dungeonmania.*;
import dungeonmania.PlayerMode.Default;
import dungeonmania.PlayerMode.Invisible;
import dungeonmania.PlayerMode.PlayerMode;
import dungeonmania.PositionPublisher.PlayerInfoPublisher;
import dungeonmania.PositionPublisher.PlayerInfoSubscriber;
import dungeonmania.StaticEntities.Portal;
import dungeonmania.util.Position;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.stream.Collectors;

public class Player extends MovingEntities implements PlayerInfoPublisher {
    private static double maxHealth;
    private static double maxAttack;
    private static int AllyAttack;
    private static int AllyDefence;
    private final List<Entity> allies;
    private final Queue<PlayerMode> modes;
    private final List<PlayerInfoSubscriber> subscribers;
    private final List<Entity> backpack;
    private int EnemiesKilled;
    private List<Buff> buffs;

    public Player(int x, int y, String type) {
        super(type, false, false, new Position(x, y), maxAttack, maxHealth);
        this.backpack = new ArrayList<>();
        EnemiesKilled = 0;
        subscribers = new ArrayList<>();
        modes = new LinkedList<>();
        addMode(new Default());
        buffs = new ArrayList<>();
        allies = new ArrayList<>();
    }

    public static void setMaxHealth(double maxHealth) {
        Player.maxHealth = maxHealth;
    }

    public static void setMaxAttack(double maxAttack) {
        Player.maxAttack = maxAttack;
    }

    public static void setAllyAttack(int AllyAttack) {
        Player.AllyAttack = AllyAttack;
    }

    public static void setAllyDefence(int AllyDefence) {
        Player.AllyDefence = AllyDefence;
    }

    public List<Entity> getBackpack() {
        return backpack;
    }

    public void addMode(PlayerMode mode) {
        if (!modes.isEmpty() && modes.peek() instanceof Default) {
            modes.remove();
        }
        modes.add(mode);
    }

    public PlayerMode getMode() {
        return modes.peek();
    }

    public void newAllies(Entity allie) {
        allies.add(allie);
    }

    public boolean LoadBuffs() {
        if(getMode() instanceof Invisible) return false;
        buffs = new ArrayList<>();
        allies.forEach(e -> buffs.add(new Buff(AllyAttack, 0, AllyDefence, e.getId(), e.getType())));
        backpack.stream().filter(e -> e instanceof Weapon).forEach(e -> {
            buffs.add(((Weapon) e).getBuff());
            ((Weapon) e).setCurrDurability(((Weapon) e).getCurrDurability() - 1);
        });
        if (!(getMode() instanceof Default)) {
            buffs.add(new Buff(0, 0, 0, getMode().providerId(), getMode().providerType()));
        }
        List<Entity> scrapped = backpack.stream().filter(e -> e instanceof Weapon).filter(e -> ((Weapon) e).getCurrDurability() <= 0).collect(Collectors.toList());
        backpack.removeAll(scrapped);
        return true;
    }

    public List<Buff> getBuffs() {
        return buffs;
    }

    public void removeFromBag(String id) {
        backpack.removeIf(b -> b.getId().equals(id));
    }

    public void addToBag(Entity entity) {
        backpack.add(entity);
    }

    public int getEnemiesKilled() {
        return EnemiesKilled;
    }

    public void updateEnemiesKilled() {
        EnemiesKilled += 1;
    }

    public void move(Position offset) {
        Position moved = getPosition().translateBy(offset);
        if (Game.getGame().findEntityByPosition(moved).stream().anyMatch(entity -> entity.isBlocked(this))) return;
        Game.getGame().findEntityByPosition(moved).stream().filter(a -> a instanceof Triggerable).map(a -> ((Triggerable) a)).forEach(e -> e.triggerEffect(this));
        if (Game.getGame().findEntityByPosition(moved).stream().noneMatch(e -> e instanceof Portal)) {
            this.setPosition(moved);
        }
        notifySubscribers();
    }

    public void oneTick() {
        notifySubscribers();
        if (modes.isEmpty()) {
            modes.add(new Default());
        }
        if (modes.peek().getDuration() == 0) {
            modes.remove();
            if (modes.isEmpty()) {
                modes.add(new Default());
            }
        }
        modes.peek().oneTick();
    }

    public void subscribe(PlayerInfoSubscriber subscriber) {
        subscribers.add(subscriber);
    }

    public void unsubscribe(PlayerInfoSubscriber subscriber) {
        subscribers.remove(subscriber);
    }

    public void notifySubscribers() {
        for (PlayerInfoSubscriber subscriber : subscribers) {
            subscriber.updatePosition(getPosition(), getMode());
        }
    }

    @Override
    public void move() {}

}
