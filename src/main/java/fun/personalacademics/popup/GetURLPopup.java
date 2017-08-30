package fun.personalacademics.popup;

import javafx.scene.control.TextField;
import javafx.scene.layout.GridPane;

import java.net.MalformedURLException;
import java.net.URL;

import javafx.scene.control.Alert;

@SuppressWarnings("restriction")
public class GetURLPopup extends Alert{
	
	private TextField urlTextBox;

	public GetURLPopup() {
		super(AlertType.CONFIRMATION);
		setTitle("Enter URL");
		setHeaderText("Please enter URL");
		urlTextBox = new TextField();
		GridPane pane = new GridPane();
		pane.addRow(0, urlTextBox);
		getDialogPane().setContent(pane);
	}
	
	public String getURLPath(){
		return urlTextBox.getText();
	}
	
	public URL getURL() throws MalformedURLException{
		return new URL(urlTextBox.getText());
	}
	

}