package staff.test;

import staff.StaffMember;
import staff.Lecturer;


import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.LocalDate;

/**
 * Tests for StaffMember and Lecturer
 * @author Zeal L
 */
public class StaffTest {

    public static void printStaffDetails(StaffMember person) {
        System.out.println(person);
    }

    @Test
    public void testStaffMember() {
        StaffMember staffMember = new StaffMember("Zeal", 100, LocalDate.of(2019, 9, 1), 
                                                LocalDate.of(2023, 6, 2));
        assertEquals("Zeal", staffMember.getName());
        assertEquals(100, staffMember.getSalary());
        assertEquals(LocalDate.of(2019, 9, 1), staffMember.getHireDate());
        assertEquals(LocalDate.of(2023, 6, 2), staffMember.getEndDate());
    }

    public static void main(String[] args) {
        StaffMember staffMember = new StaffMember("Zeal", 100, LocalDate.of(2019, 9, 1), 
                                                LocalDate.of(2023, 6, 2));
        StaffMember lecturer = new Lecturer("James", 1000000, LocalDate.of(2019, 9, 1), 
                                            LocalDate.of(2023, 6, 2), "CSE", 'C');
        printStaffDetails(staffMember);
        printStaffDetails(lecturer);
        System.out.println(staffMember.equals(staffMember));
        System.out.println(lecturer.equals(lecturer));
        System.out.println(staffMember.equals(lecturer));
        System.out.println(lecturer.equals(staffMember));
    }
}
