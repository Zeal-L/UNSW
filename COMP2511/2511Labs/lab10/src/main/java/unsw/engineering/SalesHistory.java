package unsw.engineering;

public class SalesHistory {
	
	private Employee salesPerson;
	
	public String getSalesSummary() {
		return salesPerson.getFirstName() + salesPerson.getLastName() + "Sales Target: " + salesPerson.getSalesTarget() + "$\n" +
			    "Sales to date: " + salesPerson.getSalesAchieved() + "$";
	}

}
