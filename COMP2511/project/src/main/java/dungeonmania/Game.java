package dungeonmania;

import dungeonmania.Battle.Battle;
import dungeonmania.BuildableEntities.Bow;
import dungeonmania.BuildableEntities.Shield;
import dungeonmania.CollectableEntities.*;
import dungeonmania.Goal.GoalManager;
import dungeonmania.MovingEntities.*;
import dungeonmania.PositionPublisher.PlayerInfoSubscriber;
import dungeonmania.StaticEntities.*;
import dungeonmania.response.models.*;
import dungeonmania.util.Direction;
import dungeonmania.util.Position;
import org.json.JSONObject;

import java.util.*;
import java.util.stream.Collectors;

import static dungeonmania.Entity.notInMap;

/**
 * The type Game.
 */
public class Game {
    private final List<Entity> entities;
    private final String dungeonName;
    private final String configName;
    private final List<Battle> battles;
    private Player player;
    private int MinMapX;
    private int MinMapY;
    private int MaxMapX;
    private int MaxMapY;
    private final GoalManager goalManager;
    private static Game game;
    
    
    public static synchronized Game getGame(JSONObject dungeonJson, JSONObject configJson, String dungeonName, String configName) {
        if (game == null) {
			game = new Game(dungeonJson, configJson, dungeonName, configName);
		}
        return game;
    }

    public static synchronized Game getGame() {
		return game;
	}


    /**
     * Instantiates a new Game.
     *
     * @param dungeonJson the dungeon json
     * @param configJson  the config json
     * @param dungeonName the dungeon name
     * @param configName  the config name
     * @throws IllegalArgumentException the illegal argument exception
     */
    private Game(JSONObject dungeonJson, JSONObject configJson, String dungeonName, String configName) throws IllegalArgumentException {
        entities = new ArrayList<>();
        Entity.resetIdCounter();
        try {
            Player.setAllyAttack(configJson.getInt("ally_attack"));
            Player.setAllyDefence(configJson.getInt("ally_defence"));
            Mercenary.setBribedRadius(configJson.getInt("bribe_radius"));
            Mercenary.setBribeAmount(configJson.getInt("bribe_amount"));
            Bomb.setBombRadius(configJson.getInt("bomb_radius"));
            Bow.setDurability(configJson.getInt("bow_durability"));
            Player.setMaxHealth(configJson.getDouble("player_health"));
            Player.setMaxAttack(configJson.getDouble("player_attack"));
            InvincibilityPotion.setMaxDuration(configJson.getInt("invincibility_potion_duration"));
            InvisibilityPotion.setMaxDuration(configJson.getInt("invisibility_potion_duration"));
            Mercenary.setMaxHealth(configJson.getDouble("mercenary_health"));
            Mercenary.setMaxAttack(configJson.getDouble("mercenary_attack"));
            Spider.setMaxAttack(configJson.getDouble("spider_attack"));
            Spider.setMaxHealth(configJson.getDouble("spider_health"));
            Spider.setSpawnRate(configJson.getInt("spider_spawn_rate"));
            Shield.setDurability(configJson.getInt("shield_durability"));
            Shield.setDefense(configJson.getInt("shield_defence"));
            Sword.setAttack(configJson.getInt("sword_attack"));
            Sword.setDurability(configJson.getInt("sword_durability"));
            ZombieToast.setMaxAttack(configJson.getDouble("zombie_attack"));
            ZombieToast.setMaxHealth(configJson.getDouble("zombie_health"));
            ZombieToastSpawner.setSpawnRate(configJson.getInt("zombie_spawn_rate"));
            for (int i = 0; i < dungeonJson.getJSONArray("entities").length(); i++) {
                JSONObject entity = dungeonJson.getJSONArray("entities").getJSONObject(i);
                String type = entity.getString("type");
                if (type.startsWith("player")) {
                    this.player = new Player(entity.getInt("x"), entity.getInt("y"),type);
                    entities.add(this.player);
                } else if (type.startsWith("wall"))
                    entities.add(new Wall(entity.getInt("x"), entity.getInt("y"), type));
                else if (type.startsWith("exit"))
                    entities.add(new Exit(entity.getInt("x"), entity.getInt("y"), type));
                else if (type.startsWith("boulder"))
                    entities.add(new Boulder(entity.getInt("x"), entity.getInt("y"), type));
                else if (type.startsWith("switch"))
                    entities.add(new FloorSwitch(entity.getInt("x"), entity.getInt("y"), type));
                else if (type.startsWith("door"))
                    entities.add(new Door(entity.getInt("x"), entity.getInt("y"), entity.getInt("key"), type));
                else if (type.startsWith("portal"))
                    entities.add(new Portal(entity.getInt("x"), entity.getInt("y"), entity.getString("colour"), type));
                else if (type.startsWith("zombie_toast_spawner"))
                    entities.add(new ZombieToastSpawner(entity.getInt("x"), entity.getInt("y"), type));
                else if (type.startsWith("spider"))
                    entities.add(new Spider(entity.getInt("x"), entity.getInt("y"), type));
                else if (type.startsWith("zombie_toast"))
                    entities.add(new ZombieToast(entity.getInt("x"), entity.getInt("y"), type));
                else if (type.startsWith("mercenary"))
                    entities.add(new Mercenary(entity.getInt("x"), entity.getInt("y"), type));
                else if (type.startsWith("treasure"))
                    entities.add(new Treasure(entity.getInt("x"), entity.getInt("y"), type));
                else if (type.startsWith("key"))
                    entities.add(new Key(entity.getInt("x"), entity.getInt("y"), entity.getInt("key"), type));
                else if (type.startsWith("invincibility_potion"))
                    entities.add(new InvincibilityPotion(entity.getInt("x"), entity.getInt("y"), type));
                else if (type.startsWith("invisibility_potion"))
                    entities.add(new InvisibilityPotion(entity.getInt("x"), entity.getInt("y"), type));
                else if (type.startsWith("wood"))
                    entities.add(new Wood(entity.getInt("x"), entity.getInt("y"), type));
                else if (type.startsWith("arrow"))
                    entities.add(new Arrows(entity.getInt("x"), entity.getInt("y"), type));
                else if (type.startsWith("bomb"))
                    entities.add(new Bomb(entity.getInt("x"), entity.getInt("y"), type));
                else if (type.startsWith("sword"))
                    entities.add(new Sword(entity.getInt("x"), entity.getInt("y"), type));
                else throw new IllegalArgumentException("Could not load file, unknown entity type: " + type);
            }
            goalManager = new GoalManager(configJson.getInt("enemy_goal"), configJson.getInt("treasure_goal"), dungeonJson.getJSONObject("goal-condition"));
        } catch (Exception e) {
            throw new IllegalArgumentException("Could not load file: " + e.getMessage());
        }
        this.dungeonName = dungeonName;
        this.configName = configName;
        reloadMapSize();
        getEntitiesByInstance(PlayerInfoSubscriber.class).forEach(e -> player.subscribe(e));
        player.notifySubscribers();
        battles = new ArrayList<>();
    }

    /**
     * get distance between two position
     *
     * @return distance
     */
    public static int getDistance(Position position1, Position position2) {
        return Math.max(Math.abs(position1.getY() - position2.getY()), Math.abs(position1.getX() - position2.getX()));
    }

    /**
     * get Precise Distance between two position
     *
     * @return distance
     */
    public static double getPreciseDistance(Position position1, Position position2) {
        return Math.sqrt(Math.pow(position1.getY() - position2.getY(), 2) + Math.pow(position1.getX() - position2.getX(), 2));
    }

    public static List<Position> cardinallyAdjacent(Position position) {
        return Arrays.asList(position.translateBy(Direction.UP),
                position.translateBy(Direction.DOWN),
                position.translateBy(Direction.LEFT),
                position.translateBy(Direction.RIGHT));
    }

    public void oneTick() {
        reloadMapSize();
        player.oneTick();
        getEntitiesByInstance(MovingEntities.class).forEach(entity -> entity.move());
        Spider.spawner();
        getEntitiesByInstance(ZombieToastSpawner.class).forEach(entity -> entity.spawn());
    }

    public void reloadMapSize() {
        this.MaxMapX = entities.stream().filter(e -> e.getPosition() != notInMap).mapToInt(e -> e.getPosition().getX()).max().getAsInt() + 2;
        this.MaxMapY = entities.stream().filter(e -> e.getPosition() != notInMap).mapToInt(e -> e.getPosition().getY()).max().getAsInt() + 2;
        this.MinMapX = entities.stream().filter(e -> e.getPosition() != notInMap).mapToInt(e -> e.getPosition().getX()).min().getAsInt() - 2;
        this.MinMapY = entities.stream().filter(e -> e.getPosition() != notInMap).mapToInt(e -> e.getPosition().getY()).min().getAsInt() - 2;
    }

    public Map<String, Integer> getMapSize() {
        Map<String, Integer> mapSize = new HashMap<>();
        mapSize.put("MaxMapX", MaxMapX);
        mapSize.put("MaxMapY", MaxMapY);
        mapSize.put("MinMapX", MinMapX);
        mapSize.put("MinMapY", MinMapY);
        return mapSize;
    }

    public void newBattle(MovingEntities enemy, String type, String enemyId) {
        if(!player.LoadBuffs()) return;
        Battle battle = new Battle(enemy, type, player);
        if (battle.start()) {
            entities.removeIf(e -> e.getId().equals(enemyId));
            player.updateEnemiesKilled();
        } else {
            entities.remove(player);
        }
        battles.add(battle);
    }

    public boolean inMap(Position position) {
        return position.getX() >= MinMapX && position.getX() <= MaxMapX && position.getY() >= MinMapY && position.getY() <= MaxMapY;
    }

    public Player getPlayer() {
        return player;
    }

    /**
     * get all Game as DungeonResponse
     *
     * @return the dungeon response
     */
    public DungeonResponse CovertToResponse() {
        return new DungeonResponse(dungeonName, configName,
                CovertToEntityResponse(),
                CovertPlayerBackPackToItemResponse(),
                CoverToBattleResponse(),
                getAllBuildableEntity(),
                goalManager.getGoal());
    }

    /**
     * Gets all entitys in map.
     *
     * @return the all entitys in map
     */
    public List<Entity> getAllEntityInMap() {
        return entities.stream().filter(entity -> entity.getPosition() != notInMap).collect(Collectors.toList());
    }

    /**
     * Covert to entity in map as the "EntityResponse" class.
     *
     * @return the list
     */
    public List<EntityResponse> CovertToEntityResponse() {
        return getAllEntityInMap().stream().map(entity -> new EntityResponse(entity.getId(), entity.getType(), entity.getPosition(), entity.isInteractable())).collect(Collectors.toList());
    }

    public List<BattleResponse> CoverToBattleResponse() {
        return battles.stream().
                map(battle -> new BattleResponse(battle.getEnemyType(),
                        battle.getRounds().stream().
                                map(r -> new RoundResponse(r.getDeltaPlayerHealth(), r.getDeltaEnemyHealth(), r.getWeaponryUsed())).
                                collect(Collectors.toList()), battle.getInitialPlayerHealth(), battle.getInitialEnemyHealth())).
                collect(Collectors.toList());
    }

    /**
     * Covert player backpack to item response.
     *
     * @return the list
     */
    public List<ItemResponse> CovertPlayerBackPackToItemResponse() {
        return player.getBackpack().stream().map(item -> new ItemResponse(item.getId(), item.getType())).collect(Collectors.toList());
    }

    public List<String> getAllBuildableEntity() {
        List<String> buildable = new ArrayList<>();
        if (Bow.checkRecipe(player.getBackpack())) buildable.add("bow");
        if (Shield.checkRecipe(player.getBackpack())) buildable.add("shield");
        return buildable;
    }

    /**
     * Find entitys by position list.
     *
     * @param position the position
     * @return the list
     */
    public List<Entity> findEntityByPosition(Position position) {
        if (position == notInMap) return new ArrayList<>();
        return entities.stream().filter(entity -> entity.getPosition() != notInMap && entity.getPosition().equals(position)).collect(Collectors.toList());
    }

    /**
     * Find entitys by type list.
     *
     * @param type the type
     * @return the list
     */
    public List<Entity> findEntityByType(String type) {
        return entities.stream().filter(entity -> entity.getType().startsWith(type)).collect(Collectors.toList());
    }

    /**
     * Gets entities.
     *
     * @return the entities
     */
    public List<Entity> getEntities() {
        return entities;
    }

    /**
     * Remove entity.
     *
     * @param entity the Entity
     */
    public void removeEntity(Entity entity) {
        entities.remove(entity);
    }

    /**
     * Add entity.
     *
     * @param entity the Entity
     */
    public void addEntity(Entity entity) {
        entities.add(entity);
    }

    /**
     * find entity in range
     *
     * @return List of Entity
     */
    public List<Entity> findEntityInRange(Position position, int range) {
        return entities.stream().
                filter(entity -> Game.getDistance(position, entity.getPosition()) <= range).
                collect(Collectors.toList());
    }

    public Entity findEntityById(String Id) {
        return entities.stream().filter(e -> e.getId().equals(Id)).findFirst().orElse(null);
    }

    /**
     * get the entity that Instance by Type
     *
     * @return List<T>
     */
    public <T> List<T> getEntitiesByInstance(Class<T> t) {
        return entities.stream()
                .filter(t::isInstance)
                .map(t::cast)
                .collect(Collectors.toList());
    }

    /**
     * check if any specified type of entity is nearBy by the given entity
     * then return those entities
     *
     * @return boolean
     */
    public <T> List<T> checkEntityNearby(Entity me, Class<T> specified) {
        return Game.cardinallyAdjacent(me.getPosition()).stream()
                .map(this::findEntityByPosition)
                .map(entities -> entities.stream()
                        .filter(specified::isInstance).collect(Collectors.toList()))
                .flatMap(List::stream).map(specified::cast).collect(Collectors.toList());
    }
}


