package staff;

import java.time.LocalDate;

/**
 * A Lecturer
 * @author Zeal L
 *
 */
public class Lecturer extends StaffMember {
    private String school;
    private char academic_status;

    /**
     * Lecturer Constructor
     * @param name
     * @param salary
     * @param hire_date
     * @param end_date
     * @param school
     * @param academic_status
     */
    public Lecturer(String name, int salary, LocalDate hire_date, LocalDate end_date, String school, char academic_status) {
        super(name, salary, hire_date, end_date);
        this.school = school;
        this.academic_status = academic_status;
    }
    /** 
     * Returns the school that the lecturer belongs to
     */
    public String getSchool() {
        return school;
    }

    /** 
     * Setter for school
     * @param school
     */
    public void setSchool(String school) {
        this.school = school;
    }

    /** 
     * Returns the academic status of the lecturer
     */
    public char getAcademicStatus() {
        return academic_status;
    }

    /** 
     * Setter for academic status
     * @param academic_status
     */
    public void setAcademicStatus(char academic_status) {
        this.academic_status = academic_status;
    }

    // An overriding toString() method that includes the school name and academic level.
    @Override
    public String toString() {
        // A for an Associate Lecturer, B  for a Lecturer, and C for a Senior Lecturer
        String level;
        switch (academic_status) {
            case 'A':
                level = "Associate Lecturer";
                break;
            case 'B':
                level = "Lecturer";
                break;
            case 'C':
                level = "Senior Lecturer";
                break;
            default:
                level = "Unknown";
                break;
        }
        return super.toString() + "[school: " + this.school + ", " + level + "]";
    }

    // Overridden equals(..) methods.
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        Lecturer other = (Lecturer) obj;
        super.equals(obj);
        if (this.getAcademicStatus() != other.getAcademicStatus())
            return false;
        return true;
    }
}