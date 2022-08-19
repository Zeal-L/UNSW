package dungeonmania;

import dungeonmania.BuildableEntities.Bow;
import dungeonmania.BuildableEntities.Shield;
import dungeonmania.exceptions.InvalidActionException;
import dungeonmania.response.models.DungeonResponse;
import dungeonmania.util.Direction;
import dungeonmania.util.FileLoader;
import org.json.JSONObject;

import java.io.IOException;
import java.util.List;

public class DungeonManiaController {
    /**
     * /dungeons
     */
    public static List<String> dungeons() {
        return FileLoader.listFileNamesInResourceDirectory("dungeons");
    }

    /**
     * /configs
     */
    public static List<String> configs() {
        return FileLoader.listFileNamesInResourceDirectory("configs");
    }

    public String getSkin() {
        return "default";
    }

    public String getLocalisation() {
        return "en_US";
    }

    /**
     * /game/new
     */
    public DungeonResponse newGame(String dungeonName, String configName) throws IllegalArgumentException {
        JSONObject dungeonJson;
        JSONObject configJson;
        if (dungeonName.isEmpty() || configName.isEmpty()) {
            throw new IllegalArgumentException("dungeonName cannot be null or empty");
        }
        try {
            dungeonJson = new JSONObject(FileLoader.loadResourceFile("/dungeons/" + dungeonName + ".json"));
            configJson = new JSONObject(FileLoader.loadResourceFile("/configs/" + configName + ".json"));
        } catch (IOException e) {
            throw new IllegalArgumentException("Could not load file: " + e.getMessage());
        }
        return Game.getGame(dungeonJson, configJson, dungeonName, configName).CovertToResponse();
    }

    /**
     * /game/dungeonResponseModel
     */
    public DungeonResponse getDungeonResponseModel() {
        return Game.getGame().CovertToResponse();
    }

    /**
     * /game/tick/item
     */
    public DungeonResponse tick(String itemUsedId) throws IllegalArgumentException, InvalidActionException {
        if (Game.getGame().getEntities().stream().filter(e -> e instanceof Usable).noneMatch(e -> e.getId().equals(itemUsedId))) {
            throw new IllegalArgumentException("Used item does not exist");
        }
        if (Game.getGame().getPlayer().getBackpack().stream().noneMatch(e -> e.getId().equals(itemUsedId))) {
            throw new InvalidActionException("itemUsed is not in the player's inventory");
        }
        ((Usable) Game.getGame().findEntityById(itemUsedId)).use();
        Game.getGame().oneTick();
        return Game.getGame().CovertToResponse();
    }

    /**
     * /game/tick/movement
     */
    public DungeonResponse tick(Direction movementDirection) {
        Game.getGame().getPlayer().move(movementDirection.getOffset());
        Game.getGame().oneTick();
        return Game.getGame().CovertToResponse();
    }

    /**
     * /game/build
     */
    public DungeonResponse build(String buildable) throws IllegalArgumentException, InvalidActionException {
        if (buildable.startsWith("bow")) {
            Bow.build(Game.getGame().getPlayer());
        } else if (buildable.startsWith("shield")) {
            Shield.build(Game.getGame().getPlayer());
        } else {
            throw new IllegalArgumentException("not one of bow, shield");
        }
        Game.getGame().oneTick();
        return Game.getGame().CovertToResponse();
    }

    /**
     * /game/interact
     */
    public DungeonResponse interact(String entityId) throws IllegalArgumentException, InvalidActionException {
        if (Game.getGame().getEntities().stream().filter(e -> e instanceof Interactive).noneMatch(e -> e.getId().equals(entityId))) {
            throw new IllegalArgumentException();
        }
        for (Interactive e : Game.getGame().getEntitiesByInstance(Interactive.class)) {
            e.interact();
        }
        Game.getGame().oneTick();
        return Game.getGame().CovertToResponse();
    }
}
