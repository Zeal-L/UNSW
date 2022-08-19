package unsw.sso.providers;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import unsw.sso.Browser;
import unsw.sso.Token;

public class InstaHam {
    private Map<String, Browser> users = new HashMap<>();
    private Map<String, Set<String>> userCodes = new HashMap<>();

    public void addUser(String email, Browser browser) {
        users.put(email, browser);
        userCodes.put(email, new HashSet<>());
    }

    private Token getToken(String email, String code) {
        if (userCodes.containsKey(email) && userCodes.get(email).contains(code)) {
            userCodes.get(email).remove(code);
            return new Token(code, email, getClass().getSimpleName());
        } else {
            // invalid!
            return new Token(null, email, getClass().getSimpleName());
        }
    }

    public void broadcastCode(String email) {
        if (users.containsKey(email)) {
            Thread thread = new Thread(() -> {
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }

                String code = UUID.randomUUID().toString();
                userCodes.get(email).add(code);
                users.get(email).interact(getToken(email, code));
            });
            thread.start();
        }
    }
}
