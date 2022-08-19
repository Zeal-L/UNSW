package dungeonmania;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.json.JSONObject;

import dungeonmania.response.models.DungeonResponse;
import dungeonmania.response.models.EntityResponse;
import dungeonmania.response.models.ItemResponse;
import dungeonmania.util.FileLoader;

public class TestUtils {
    public static Stream<EntityResponse> getEntitiesStream(DungeonResponse res, String type) {
        if (type.equals("zombie_toast")){
            return res.getEntities().stream()
                    .filter(it -> it.getType().startsWith(type))
                    .filter(it -> !it.getType().startsWith("zombie_toast_spawner"));
        }
        return res.getEntities().stream().filter(it -> it.getType().startsWith(type));
    }

    public static int countEntityOfType(DungeonResponse res, String type) {
        return getEntities(res, type).size();
    }
    
    public static Optional<EntityResponse> getPlayer(DungeonResponse res) {
        return getEntitiesStream(res, "player").findFirst();
    }

    public static List<EntityResponse> getEntities(DungeonResponse res, String type) {
        return getEntitiesStream(res, type).collect(Collectors.toList());
    }

    public static List<ItemResponse> getInventory(DungeonResponse res, String type) {
        return res.getInventory().stream()
                                 .filter(it -> it.getType().startsWith(type))
                                 .collect(Collectors.toList());
    }

    public static String getGoals(DungeonResponse dr) {
        String goals = dr.getGoals();
        return goals != null ? goals : "";
    }

    public static String getValueFromConfigFile(String fieldName, String configFilePath) {
        try {
            JSONObject config = new JSONObject(FileLoader.loadResourceFile("/configs/" + configFilePath + ".json"));
            
            if (!config.isNull(fieldName)) {
                return config.get(fieldName).toString();
            }
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
        
        return null;
    }

    
}
