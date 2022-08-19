package unsw.sso;

import java.util.HashMap;
import java.util.Map;

import unsw.sso.providers.Hoogle;
import unsw.sso.providers.LinkedOut;

public class ClientApp {
    private boolean hasHoogle = false;
    private Map<String, Boolean> usersExist = new HashMap<>();
    private final String name;

    public ClientApp(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    // TODO: you'll probably want to change a lot of this class
    public void registerProvider(Object o) {
        if (o instanceof Hoogle) {
            hasHoogle = true;
        }    
    }

    public boolean hasHoogle() {
        return hasHoogle;
    }

    public boolean hasLinkedOut() {
        return true;
    }

    public void registerUser(Token token) {
        // only hoogle is supported right now!  So we presume hoogle on user
        usersExist.put(token.getUserEmail(), true);
    }

    public boolean hasUserForProvider(String email, Object provider) {
        if (provider instanceof LinkedOut) {
            return true;
        }
        
        return provider instanceof Hoogle && this.hasHoogle && this.usersExist.getOrDefault(email, false);
    }

    public boolean hasHoogleUser(String email) {
        return usersExist.getOrDefault(email, false);
    }
}
