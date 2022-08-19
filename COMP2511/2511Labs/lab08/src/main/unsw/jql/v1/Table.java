package unsw.jql.v1;

import java.util.List;

public class Table<E> {
    private List<E> records;

    public Table(List<E> records) {
        this.records = records;
    }

    public TableView<E> toView() {
        return new SimpleTableView<E>(records);
    }
}
