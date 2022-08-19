package unsw.jql.v2;

import java.util.Objects;

public class User {
    private final boolean isActive;
    private final String userId;
    private final String jobTitle;

    public User(boolean isActive, String userId, String jobTitle) {
        this.isActive = isActive;
        this.userId = userId;
        this.jobTitle = jobTitle;
    }

    public boolean isActive() {
        return isActive;
    }

    public String userId() {
        return userId;
    }

    public String jobTitle() {
        return jobTitle;
    }

    @Override
    public String toString() {
        return "User [isActive=" + isActive + ", jobTitle=" + jobTitle + ", userId=" + userId + "]";
    }

    @Override
    public int hashCode() {
        return Objects.hash(isActive, jobTitle, userId);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        User other = (User) obj;
        return isActive == other.isActive && Objects.equals(jobTitle, other.jobTitle)
                && Objects.equals(userId, other.userId);
    }
}
