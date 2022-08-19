package dungeonmania;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Buff {
    private final int addAttack;
    private final int multiplyAttack;
    private final int addDefence;
    private final String providerId;
    private final String providerType;

    public Buff(int addAttack, int multiplyAttack, int addDefence, String Id, String Type) {
        this.addAttack = addAttack;
        this.multiplyAttack = multiplyAttack;
        this.addDefence = addDefence;
        this.providerId = Id;
        this.providerType = Type;
    }

    public static Map<String, Integer> calculateBuff(List<Buff> buffs) {
        int AddAttack = 0;
        int MultiplyAttack = 0;
        int AddDefence = 0;
        for (Buff b : buffs) {
            AddAttack += b.addAttack;
            MultiplyAttack += b.multiplyAttack;
            AddDefence += b.addDefence;
        }
        int finalAddAttack = AddAttack;
        int finalMultiplyAttack = MultiplyAttack == 0 ? 1 : MultiplyAttack;
        int finalAddDefence = AddDefence;
        return new HashMap<>() {{
            put("addAttack", finalAddAttack);
            put("multiplyAttack", finalMultiplyAttack);
            put("addDefence", finalAddDefence);
        }};
    }

    public String getProviderId() {
        return providerId;
    }

    public String getProviderType() {
        return providerType;
    }
}
