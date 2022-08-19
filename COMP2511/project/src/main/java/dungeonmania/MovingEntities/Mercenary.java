package dungeonmania.MovingEntities;

import dungeonmania.CollectableEntities.Treasure;
import dungeonmania.Entity;
import dungeonmania.Game;
import dungeonmania.Interactive;
import dungeonmania.MercenaryBehavior.*;
import dungeonmania.PlayerMode.Invincible;
import dungeonmania.PlayerMode.Invisible;
import dungeonmania.PlayerMode.PlayerMode;
import dungeonmania.PositionPublisher.PlayerInfoSubscriber;
import dungeonmania.StaticEntities.Portal;
import dungeonmania.Triggerable;
import dungeonmania.exceptions.InvalidActionException;
import dungeonmania.util.Position;

import java.util.List;
import java.util.stream.Collectors;

public class Mercenary extends MovingEntities implements PlayerInfoSubscriber, Interactive, Triggerable {
    public static double maxAttack;
    private static int bribedRadius;
    private static int bribeAmount;
    private static double maxHealth;
    private MercenaryBehavior behavior;
    private Position playerPosition;

    public Mercenary(int x, int y, String type) {
        super(type, false, true, new Position(x, y),maxAttack,maxHealth);
        behavior = new NotBribed();
    }

    public static void setBribedRadius(int bribedRadius) {
        Mercenary.bribedRadius = bribedRadius;
    }

    public static void setBribeAmount(int bribeAmount) {
        Mercenary.bribeAmount = bribeAmount;
    }

    public static void setMaxHealth(double maxHealth) {
        Mercenary.maxHealth = maxHealth;
    }

    public static void setMaxAttack(double maxAttack) {
        Mercenary.maxAttack = maxAttack;
    }

    @Override
    public void triggerEffect(Entity entity) {
        if (entity instanceof Player && !(behavior instanceof Bribed)) {
            Game.getGame().newBattle(this, this.getType(), this.getId());
            if (getCurrHealth() <= 0){
                Game.getGame().getPlayer().unsubscribe(this);
            }
        }
    }

    @Override
    public void move() {
        Position next = behavior.action(this);
        Game.getGame().findEntityByPosition(next).stream().filter(a -> a instanceof Triggerable).map(a -> ((Triggerable) a)).forEach(e -> e.triggerEffect(this));
        Game.getGame().findEntityByPosition(next).forEach(e -> this.triggerEffect(e));
        if (Game.getGame().findEntityByPosition(next).stream().noneMatch(e -> e instanceof Portal)) this.setPosition(next);
    }

    public void interact() throws InvalidActionException {
        if (behavior instanceof Bribed) return;
        Player player = Game.getGame().getPlayer();
        if (Game.getDistance(getPlayerPosition(), getPosition()) > bribedRadius)
            throw new InvalidActionException("player is not within specified bribing radius to the mercenary");
        List<Entity> treasures = player.getBackpack().stream().filter(e -> e instanceof Treasure).collect(Collectors.toList());
        if (treasures.size() < bribeAmount)
            throw new InvalidActionException("player does not have enough gold and attempts to bribe a mercenary");
        treasures.stream().limit(bribeAmount).forEach(e -> player.removeFromBag(e.getId()));
        behavior = new Bribed();
        player.newAllies(this);
    }

    @Override
    public void updatePosition(Position position, PlayerMode mode) {
        playerPosition = position;
        if (!(behavior instanceof Bribed)) {
            if (mode instanceof Invincible) {
                behavior = new Runaway();
            } else if (mode instanceof Invisible) {
                behavior = new Blind();
            } else {
                behavior = new NotBribed();
            }
        }
    }

    public Position getPlayerPosition() {
        return playerPosition;
    }
}
