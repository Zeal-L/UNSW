package staff;

import java.time.LocalDate;

/**
 * A staff member
 * @author Robert Clifton-Everest, Zeal L
 *
 */
public class StaffMember {
    private String name;
    private int salary;
    private LocalDate hire_date;
    private LocalDate end_date;

    /**
     * StaffMember Constructor
     * @param name
     * @param salary
     * @param hire_date
     * @param end_date
     */
    public StaffMember(String name, int salary, LocalDate hire_date, LocalDate end_date) {
        this.name = name;
        this.salary = salary;
        this.hire_date = hire_date;
        this.end_date = end_date;
    }
    
    /** 
     * Returns the name of the staff member
     */
    public String getName() {
        return name;
    }
    
    /** 
     * Setter for name
     * @param name
     */
    public void setName(String name) {
        this.name = name;
    }
    
    /** 
     * Returns the salary of the staff member
     */
    public int getSalary() {
        return salary;
    }
    
    /** 
     * Setter for salary
     * @param salary
     */
    public void setSalary(int salary) {
        this.salary = salary;
    }
    
    /** 
     * Returns the Hire Date of the staff member
     */
    public LocalDate getHireDate() {
        return hire_date;
    }
    
    /** 
     * Setter for hire date
     * @param hire_date
     */
    public void setHireDate(LocalDate hire_date) {
        this.hire_date = hire_date;
    }
    
    /** 
     * Returns the End Date of the staff member
     */
    public LocalDate getEndDate() {
        return end_date;
    }
    
    /** 
     * Setter for end date
     * @param end_date
     */
    public void setEndDate(LocalDate end_date) {
        this.end_date = end_date;
    }

    // An overriding toString() method
    @Override
    public String toString() {
        return this.getName() + "[name: " + this.name + 
            ", salary: " + this.salary + 
            ", hire_date: " + this.hire_date + 
            ", end_date: " + this.end_date + "]";
    }

    // An overridden equals() methods.
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        StaffMember other = (StaffMember) obj;
        if (name == null) {
            if (other.name != null)
                return false;
        } else if (!name.equals(other.name))
            return false;
        if (salary != other.salary)
            return false;
        if (hire_date == null) {
            if (other.hire_date != null)
                return false;
        } else if (!hire_date.equals(other.hire_date))
            return false;
        if (end_date == null) {
            if (other.end_date != null)
                return false;
        } else if (!end_date.equals(other.end_date))
            return false;
        return true;
    }
}

