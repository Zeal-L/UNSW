package unsw.crown;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javafx.animation.KeyFrame;
import javafx.animation.Timeline;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.geometry.HPos;
import javafx.geometry.Pos;
import javafx.geometry.VPos;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.paint.Paint;
import javafx.scene.shape.Rectangle;
import javafx.util.Duration;

/**
 * @author Braedon Wooding, and @your name
 */
public class CheckerController {
    @FXML
    public GridPane grid;

    @FXML
    public HBox startMenu;

    @FXML
    public CheckBox quackering;

    @FXML
    public Button gameButton;

    private CheckerColor turn = CheckerColor.RED;

    private Checkerboard board;
    private Position selectedCheckerPos;
    private List<Rectangle> highlightedSquares = new ArrayList<>();
    private Map<Position, Set<Position>> possiblePredecessors = new HashMap<>();

    private void clearSelected() {
        // clear checker
        this.selectedCheckerPos = null;
        for (Rectangle r : highlightedSquares) {
            grid.getChildren().remove(r);
        }
        highlightedSquares.clear();
        possiblePredecessors.clear();
    }

    private void checkerClicked(MouseEvent event) {
        // get all possible squares
        Node clickedNode = event.getPickResult().getIntersectedNode();
        if (clickedNode.equals(grid) == false) {
            // click on descendant node
            Integer colIndex = GridPane.getColumnIndex(clickedNode);
            Integer rowIndex = GridPane.getRowIndex(clickedNode);
            if (colIndex == null || rowIndex == null) {
                colIndex = GridPane.getColumnIndex(clickedNode.getParent());
                rowIndex = GridPane.getRowIndex(clickedNode.getParent());
            }  

            Position clickedPos = new Position(colIndex, rowIndex);
            Checker clickedChecker = board.getPieceAt(clickedPos);

            if (selectedCheckerPos != null && clickedChecker == null) {
                // verify that indeed the clicked square is valid
                Checker selected = board.getPieceAt(selectedCheckerPos);
                if (selected != null && selected.getColor().equals(turn)) {
                    List<Position> moves = processMoves(selectedCheckerPos, clickedPos);
                    if (moves != null && moves.size() > 0) {
                        moves.add(clickedPos);
                        Timeline timeline = new Timeline(
                                new KeyFrame(Duration.seconds(0.1), new EventHandler<ActionEvent>() {
                                    private int i = 1;
                                    private CheckerColor nextTurn = turn.toggleColor();

                                    @Override
                                    public void handle(ActionEvent event) {
                                        if (i >= moves.size()) {
                                            turn = nextTurn;
                                        } else {
                                            board.moveChecker(moves.get(i - 1), moves.get(i));
                                            generateGrid();
                                            i++;
                                        }
                                    }
                                }), new KeyFrame(Duration.seconds(0.5)));
                        turn = null; // no one's turn
                        timeline.setCycleCount(moves.size());
                        timeline.play();
                    }

                    clearSelected();
                } else {
                    clearSelected();
                }
            } else if (clickedChecker != null && clickedChecker.getColor().equals(turn)) {
                this.clearSelected();
                this.selectedCheckerPos = clickedPos;
                recursivelyAddCheckerPositions(clickedChecker, clickedPos);
            }
        } else {
            clearSelected();
        }
    }

    private List<Position> processMoves(Position sourcePos, Position endPos) {
        if (possiblePredecessors.containsKey(endPos)) {
            for (Position pred : possiblePredecessors.get(endPos)) {
                if (pred.equals(sourcePos)) {
                    // found source
                    return new ArrayList<>(Arrays.asList(sourcePos));
                }
                List<Position> pos = processMoves(sourcePos, pred);
                if (pos != null && pos.size() > 0) {
                    // we found a path back to source!
                    // process this action
                    pos.add(pred);
                    return pos;
                }
            }
        }
        return null;
    }

    private boolean recursivelyAddCheckerPositions(Checker checker, Position source) {
        List<Position> positions = checker.validPositions(board, source);
        int validJumps = 0;
        for (Position pos : positions) {
            if (!board.isInBoundsAndEmpty(pos) ||
                (possiblePredecessors.containsKey(pos) && possiblePredecessors.get(pos).contains(source)) ||
                (possiblePredecessors.containsKey(source) && possiblePredecessors.get(source).contains(pos))) {
                // be nice to students and skip bad positions
                continue;
            }
            
            possiblePredecessors.putIfAbsent(pos, new HashSet<>());

            // check if this jumps over a piece
            Checker c = board.getPieceAt(Position.midPointPosition(source, pos));
            if (c != null && c != checker) {
                possiblePredecessors.get(pos).add(source);
                String color;
                if (recursivelyAddCheckerPositions(checker, pos)) {
                    color = "silver";
                } else {
                    color = "purple";
                }
                addPossiblePosition(pos, color);
                validJumps++;
            } else if (board.getPieceAt(source) != null) {
                possiblePredecessors.get(pos).add(source);
                addPossiblePosition(pos, "purple");
            }
        }
        return validJumps > 0;
    }

    private void addPossiblePosition(Position pos, String color) {
        Rectangle r = new Rectangle(pos.getCol() * 50, pos.getRow() * 50, 45, 45);
        r.setStroke(Paint.valueOf(color));
        r.setStrokeWidth(5);
        r.setFill(null);
        grid.add(r, pos.getCol(), pos.getRow());
        this.highlightedSquares.add(r);
    }

    private void generateGrid() {
        // we'll learn about the observer pattern soon, which makes this a lot easier
        // but for now, we'll just completely regenerate it upon each change.
        // for your project the observer pattern is recommended...

        this.grid.getChildren().clear();

        for (int col = 0; col < Checkerboard.BOARD_SIZE; col++) {
            for (int row = 0; row < Checkerboard.BOARD_SIZE; row++) {
                Rectangle square = new Rectangle(col * 50, row * 50, 50, 50);
                Position pos = new Position(col, row);

                square.setFill(Paint.valueOf(col % 2 != row % 2 ? "green" : "yellow"));
                grid.add(square, col, row);
                square.setOnMouseClicked(this::checkerClicked);

                Checker checker = board.getPieceAt(pos);
                if (checker != null) {
                    Node node = checker.getNode(col, row);
                    grid.add(node, col, row);
                    node.setOnMouseClicked(this::checkerClicked);
                    GridPane.setValignment(node, VPos.CENTER);
                    GridPane.setHalignment(node, HPos.CENTER);
                }
            }
        }
    }

    @FXML
    public void toggleGame() {
        if (this.startMenu.isVisible()) {
            this.gameButton.setText("Stop Game");
            turn = CheckerColor.RED;
            this.startMenu.setVisible(false);
            board = new Checkerboard(quackering.isSelected());
            grid.setAlignment(Pos.CENTER);
            generateGrid();
        } else {
            this.gameButton.setText("Start Game");
            this.startMenu.setVisible(true);
            board = null;
            this.grid.getChildren().clear();
        }
    }

    @FXML
    public void initialize() {
    }
}
