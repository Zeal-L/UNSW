package dungeonmania.Battle.Round;

import dungeonmania.Buff;
import dungeonmania.MovingEntities.MovingEntities;
import dungeonmania.MovingEntities.Player;
import dungeonmania.PlayerMode.Invincible;
import dungeonmania.response.models.ItemResponse;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class Round {
    private final double deltaPlayerHealth;
    private final double deltaEnemyHealth;
    private final Map<String,String> weaponryUsedBy;

    public Round(MovingEntities enemy, Player player) {
        weaponryUsedBy = new HashMap<>();
        Map<String,Integer> buffs = Buff.calculateBuff(player.getBuffs());
        if(player.getMode() instanceof Invincible) {
            deltaEnemyHealth = enemy.getCurrHealth()*(-1);
            deltaPlayerHealth = 0;
        } else {
            deltaEnemyHealth = ((buffs.get("multiplyAttack") * (player.getCurrAttack() + buffs.get("addAttack")))/5)*(-1);
            deltaPlayerHealth = ((enemy.getCurrAttack()-buffs.get("addDefence"))/10)*(-1);
        }
        player.getBuffs().forEach(e -> weaponryUsedBy.put(e.getProviderId(),e.getProviderType()));
        enemy.setCurrHealth(enemy.getCurrHealth()+deltaEnemyHealth);
        player.setCurrHealth(player.getCurrHealth()+deltaPlayerHealth);
    }
    public double getDeltaPlayerHealth() {
        return deltaPlayerHealth;
    }

    public double getDeltaEnemyHealth() {
        return deltaEnemyHealth;
    }

    public List<ItemResponse> getWeaponryUsed() {
        return weaponryUsedBy.entrySet().stream().map(e -> new ItemResponse(e.getKey(),e.getValue())).collect(Collectors.toList());
    }
}
