package dungeonmania.MovingEntities;

import dungeonmania.Entity;
import dungeonmania.Game;
import dungeonmania.PlayerMode.Invincible;
import dungeonmania.PlayerMode.PlayerMode;
import dungeonmania.PositionPublisher.PlayerInfoSubscriber;
import dungeonmania.Triggerable;
import dungeonmania.ZombieBehavior.Default;
import dungeonmania.ZombieBehavior.Runaway;
import dungeonmania.ZombieBehavior.ZombieBehavior;
import dungeonmania.util.Position;

public class ZombieToast extends MovingEntities implements PlayerInfoSubscriber, Triggerable{
    private static double maxHealth;
    private static double maxAttack;
    private Position playerPosition;
    private ZombieBehavior behavior;
    public ZombieToast(int x, int y,String type) {
        super(type, false, false, new Position(x, y),maxAttack,maxHealth);
        behavior = new Default();
    }
    public ZombieToast(int x, int y) {
        this(x,y,"zombie_toast");
    }

    public static void setMaxHealth(double maxHealth) {
        ZombieToast.maxHealth = maxHealth;
    }

    public static void setMaxAttack(double maxAttack) {
        ZombieToast.maxAttack = maxAttack;
    }


    @Override
    public void updatePosition(Position position, PlayerMode mode) {
        playerPosition = position;
        if(mode instanceof Invincible){
            behavior = new Runaway();
        } else {
            behavior = new Default();
        }
    }

    public Position getPlayerPosition() {
        return playerPosition;
    }

    @Override
    public void triggerEffect(Entity entity) {
        if(entity instanceof Player) {
            Game.getGame().newBattle(this, this.getType(), this.getId());
        }
        if (getCurrHealth() <= 0){
            Game.getGame().getPlayer().unsubscribe(this);
        }
    }

    @Override
    public void move() {
        Position next = behavior.action(this);
        Game.getGame().findEntityByPosition(next).stream().filter(a -> a instanceof Triggerable).map(a -> ((Triggerable) a)).forEach(e -> e.triggerEffect(this));
        Game.getGame().findEntityByPosition(next).forEach(e -> this.triggerEffect(e));
        this.setPosition(next);
    }

    
}
