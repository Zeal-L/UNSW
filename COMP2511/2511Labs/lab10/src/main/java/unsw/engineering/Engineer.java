package unsw.engineering;

public class Engineer extends Employee {

    private double bonus;

    public Engineer(String title, String firstName, String lastName, int quota, double bonus) {
        super(title, firstName, lastName, quota);
        this.bonus = bonus;
    }

    public double calculateSalary() {
        double totalSal;
        totalSal = super.getBaseSalary() + bonus
                 + super.calculateParkingFringeBenefits() - super.calculateTax();
        return totalSal;
    }
}
