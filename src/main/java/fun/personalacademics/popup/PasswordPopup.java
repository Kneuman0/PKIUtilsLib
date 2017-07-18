package fun.personalacademics.popup;

import javafx.scene.control.Alert;
import javafx.scene.control.TextField;
import javafx.scene.layout.GridPane;

public class PasswordPopup extends Alert{
	
	private TextField passwordTextBox;

	public PasswordPopup() {
		super(AlertType.CONFIRMATION);
		setTitle("Enter Password");
		setHeaderText("Please enter password");
		passwordTextBox = new TextField();
		GridPane pane = new GridPane();
		pane.addRow(0, passwordTextBox);
		getDialogPane().setContent(pane);
	}
	
	public String getPassword(){
		return passwordTextBox.getText();
	}

}
