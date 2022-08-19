package unsw.sso;

public class Token {
    private final String accessToken;
    private final String userEmail;
    private final String providerName;
    
    public Token(String accessToken, String userEmail, String providerName) {
        this.accessToken = accessToken;
        this.userEmail = userEmail;
        this.providerName = providerName;
    }

    public String getProviderName() {
        return providerName;
    }

    public String getUserEmail() {
        return userEmail;
    }

    public String getAccessToken() {
        return accessToken;
    }
}
