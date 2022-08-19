package unsw.enrolment;
import java.util.ArrayList;
import java.util.List;

/**
 * A course in the enrolment system.
 * @author Robert Clifton-Everest & Nick Patrikeos
 *
 */
public class Course {

    private String courseCode;
    private String title;
    private List<Course> prereqs = new ArrayList<Course>();
    private List<CourseOffering> courseOfferings = new ArrayList<CourseOffering>();

    public Course(String courseCode, String title) {
        this.courseCode = courseCode;
        this.title = title;
    }

    public void addPrereq(Course course) {
        prereqs.add(course);
    }

    public void addOffering(CourseOffering offering) {
        courseOfferings.add(offering);
    }

    public String getCourseCode() {
        return courseCode;
    }

    public List<Course> getPrereqs() {
        return prereqs;
    }

    public String getTitle() {
        return title;
    }
}
