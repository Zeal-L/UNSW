package unsw;

import spark.Request;
import spark.Spark;
import unsw.blackout.BlackoutController;
import unsw.blackout.FileTransferException;
import unsw.response.models.EntityInfoResponse;
import unsw.utils.Angle;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializer;
import com.google.gson.JsonSerializationContext;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import scintilla.Scintilla;

public class App {
    private static volatile Map<String, BlackoutController> sessionStates = new HashMap<>();

    private static synchronized BlackoutController getBlackoutController(Request request) {
        String session = request.session().id();
        if (session == null) {
            throw new RuntimeException("No State found");
        }

        if (sessionStates.containsKey(session)) {
            return sessionStates.get(session);
        } else {
            BlackoutController bc = new BlackoutController();
            sessionStates.put(session, bc);
            return bc;
        }
    }

    public static void main(String[] args) throws Exception {
        Scintilla.initialize();
        GsonBuilder gsonBuilder = new GsonBuilder();

        JsonSerializer<Angle> serializer = (Angle angle, Type typeOfId, JsonSerializationContext context) -> {
            return new JsonPrimitive(angle.toRadians());
        };
        gsonBuilder.registerTypeAdapter(Angle.class, serializer);
        Gson gson = gsonBuilder.create();

        Spark.after((request, response) -> {
            response.header("Access-Control-Allow-Origin", "*");
            response.header("Access-Control-Allow-Methods", "*");
            response.header("Access-Control-Allow-Headers", "*");
        });

        Spark.put("/api/device/", "application/json", (request, response) -> {
            BlackoutController bc = getBlackoutController(request);
            synchronized (bc) {
                Angle position = Angle.fromRadians(Double.parseDouble(request.queryParams("position")));
                boolean isMoving = Boolean.parseBoolean(request.queryParams("isMoving"));
                bc.createDevice(request.queryParams("deviceId"), request.queryParams("type"), position, isMoving);
                return "";
            }
        }, gson::toJson);

        Spark.delete("/api/device/", "application/json", (request, response) -> {
            BlackoutController bc = getBlackoutController(request);
            synchronized (bc) {
                bc.removeDevice(request.queryParams("deviceId"));
                return "";
            }
        }, gson::toJson);

        Spark.put("/api/satellite/", "application/json", (request, response) -> {
            BlackoutController bc = getBlackoutController(request);
            synchronized (bc) {
                Angle position = Angle.fromRadians(Double.parseDouble(request.queryParams("position")));
                double height = Double.parseDouble(request.queryParams("height"));
                bc.createSatellite(request.queryParams("satelliteId"), request.queryParams("type"), height, position);
                return "";
            }
        }, gson::toJson);

        Spark.delete("/api/satellite/", "application/json", (request, response) -> {
            BlackoutController bc = getBlackoutController(request);
            synchronized (bc) {
                bc.removeSatellite(request.queryParams("satelliteId"));
                return "";
            }
        }, gson::toJson);

        Spark.get("/api/entity/info/", "application/json", (request, response) -> {
            BlackoutController bc = getBlackoutController(request);
            synchronized (bc) {
                return bc.getInfo(request.queryParams("id"));
            }
        }, gson::toJson);

        Spark.post("/api/device/file/", "application/json", (request, response) -> {
            BlackoutController bc = getBlackoutController(request);
            synchronized (bc) {
                bc.addFileToDevice(request.queryParams("deviceId"), request.queryParams("fileName"), request.body());
                return "";
            }
        }, gson::toJson);

        Spark.get("/api/device/all/", "application/json", (request, response) -> {
            BlackoutController bc = getBlackoutController(request);
            synchronized (bc) {
                Map<String, EntityInfoResponse> result = new HashMap<>();
                bc.listDeviceIds().forEach(id -> result.put(id, bc.getInfo(id)));
                return result;
            }
        }, gson::toJson);

        Spark.get("/api/satellite/all/", "application/json", (request, response) -> {
            BlackoutController bc = getBlackoutController(request);
            synchronized (bc) {
                Map<String, EntityInfoResponse> result = new HashMap<>();
                bc.listSatelliteIds().forEach(id -> result.put(id, bc.getInfo(id)));
                return result;
            }
        }, gson::toJson);

        Spark.get("/api/entity/entitiesInRange/", "application/json", (request, response) -> {
            BlackoutController bc = getBlackoutController(request);
            synchronized (bc) {
                return bc.communicableEntitiesInRange(request.queryParams("id"))
                        .stream().map(e -> bc.getInfo(e)).collect(Collectors.toList());
            }
        }, gson::toJson);

        Spark.post("/api/sendFile/", "application/json", (request, response) -> {
            BlackoutController bc = getBlackoutController(request);
            synchronized (bc) {
                try {
                    bc.sendFile(request.queryParams("fileName"), request.queryParams("fromId"),
                            request.queryParams("toId"));
                    return "";
                } catch (FileTransferException ex) {
                    return ex.getClass().getSimpleName() + ":" + ex.getMessage();
                }
            }
        }, gson::toJson);

        Spark.post("/api/createSlope/", "application/json", (request, response) -> {
            BlackoutController bc = getBlackoutController(request);
            synchronized (bc) {
                bc.createSlope(Integer.parseInt(request.queryParams("startAngle")),
                        Integer.parseInt(request.queryParams("endAngle")), Integer.parseInt(request.queryParams("gradient")));
                return "";
            }
        }, gson::toJson);

        Spark.post("/api/simulate/", "application/json", (request, response) -> {
            BlackoutController bc = getBlackoutController(request);
            synchronized (bc) {
                int n;
                try {
                    n = Integer.parseInt(request.queryParamOrDefault("n", "1"));
                } catch (NumberFormatException e) {
                    n = 1;
                }
                if (n < 1)
                    n = 1;

                List<Map<String, EntityInfoResponse>> results = new ArrayList<>();
                for (int i = 0; i < n; i++) {
                    bc.simulate();

                    Map<String, EntityInfoResponse> result = new HashMap<>();
                    bc.listSatelliteIds().forEach(id -> result.put(id, bc.getInfo(id)));
                    bc.listDeviceIds().forEach(id -> result.put(id, bc.getInfo(id)));
                    results.add(result);
                }

                return results;
            }
        }, gson::toJson);

        Scintilla.start();
    }
}
