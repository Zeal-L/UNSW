package dungeonmania.Battle;

import dungeonmania.Battle.Round.Round;
import dungeonmania.MovingEntities.MovingEntities;
import dungeonmania.MovingEntities.Player;

import java.util.ArrayList;
import java.util.List;

public class Battle {
    private final MovingEntities enemy;
    private final String enemyType;
    private final Player player;
    private final List<Round> rounds;
    private final double initialPlayerHealth;
    private final double initialEnemyHealth;

    public Battle(MovingEntities enemy, String enemyType, Player player) {
        this.enemy = enemy;
        this.player = player;
        this.enemyType = enemyType;
        initialEnemyHealth = enemy.getCurrHealth();
        initialPlayerHealth = player.getCurrHealth();
        rounds = new ArrayList<>();
    }

    /**
     * @return true is player win, otherwise false
     */
    public boolean start() {
        while (true) {
            if (player.getCurrHealth() <= 0) return false;
            if (enemy.getCurrHealth() <= 0) return true;
            rounds.add(new Round(enemy, player));
        }
    }

    public double getInitialPlayerHealth() {
        return initialPlayerHealth;
    }

    public double getInitialEnemyHealth() {
        return initialEnemyHealth;
    }

    public String getEnemyType() {
        return enemyType;
    }

    public List<Round> getRounds() {
        return rounds;
    }
}
