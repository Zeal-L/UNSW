package unsw.enrolment;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.Comparator;

import unsw.enrolment.exceptions.InvalidEnrolmentException;

public class CourseOffering extends Course {

    private Course course;
    private String term;
    private List<Enrolment> enrolments = new ArrayList<Enrolment>();

    public CourseOffering(Course course, String term) {
        super(course.getCourseCode(), course.getTitle());
        this.course = course;
        this.term = term;
        this.course.addOffering(this);
    }

    public Course getCourse() {
        return course;
    }

    public List<Course> getCoursePrereqs() {
        return course.getPrereqs();
    }

    public String getTerm() {
        return term;
    }

    public Enrolment addEnrolment(Student student) throws InvalidEnrolmentException {
        if (checkValidEnrolment(student)) {
            Enrolment enrolment = new Enrolment(this, student);
            enrolments.add(enrolment);
            student.addEnrolment(enrolment);
            return enrolment;
        } else {
            throw new InvalidEnrolmentException("student has not satisfied the prerequisites");
        }
    }

    private boolean checkValidEnrolment(Student student) {
        return getCoursePrereqs().stream()
            .allMatch(prereq -> student.getEnrolments().stream()
                .filter(enrolment -> enrolment.getCourse().equals(prereq))
                .anyMatch(enrolment -> enrolment.hasPassedCourse()));
    }
    // Comparator<Student> myCmpAnonymous = new Comparator<Student>() {
    //     @Override
    //     public int compare(Student s1, Student s2) {
    //         if (s1.getProgram() != s2.getProgram()) {
    //             return s1.getProgram() - s2.getProgram();
    //         } else if (s1.getStreams().length != s2.getStreams().length) {
    //             return s1.getStreams().length - s2.getStreams().length;
    //         } else if (!s1.getName().equals(s2.getName())) {
    //             return s1.getName().compareTo(s2.getName());
    //         } else {
    //             return s1.getZid().compareTo(s2.getZid());
    //         }
    //     }
    // };  

    public List<Student> studentsEnrolledInCourse() {
        List<Student> students = enrolments.stream()
                                        .map(Enrolment::getStudent)
                                        .sorted((Student s1, Student s2) -> { if (s1.getProgram() != s2.getProgram()) { return s1.getProgram() - s2.getProgram(); } else if (s1.getStreams().length != s2.getStreams().length) { return s1.getStreams().length - s2.getStreams().length; } else if (!s1.getName().equals(s2.getName())) { return s1.getName().compareTo(s2.getName()); } else { return s1.getZid().compareTo(s2.getZid()); }})
                                        .collect(Collectors.toList());
        return students;
    }
}