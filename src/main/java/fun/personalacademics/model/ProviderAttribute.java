package fun.personalacademics.model;

import javafx.beans.property.SimpleObjectProperty;

@SuppressWarnings("restriction")
public abstract class ProviderAttribute {
	
		
	/**
	 * Enumerators for determining the type of the subclass when
	 * processing requests made from the TableTreeView
	 * @author Karottop
	 *
	 */
	public static enum ProviderAttributeType {PROVIDER, SERVICE, CERTIFICATE_BEAN, ROOT};
	
	/**
	 * This SimpleObjectProperty<Object> will be the value that
	 * updates the cells in the TableTreeView. It will be
	 * necessary to use type casting and the above Enumeration to carry out
	 * type sensitive operations
	 * 
	 * @return
	 */
	public abstract SimpleObjectProperty<ProviderAttribute> nameProperty();
	
	/**
	 * Returns the ProviderAttributeType of the subclass. This enum
	 * can be relied upon for safely type casting
	 * @return roviderAttributeType of the class
	 */
	public abstract ProviderAttributeType getType();
	
	/**
	 * This method will allow access to the instance of the subclass type. This
	 * method should not be used before checking the enumerated type for accurate
	 * specification of the generic type in the method.
	 * @return an instance of the 
	 */
	public abstract <Type extends ProviderAttribute> Type getEncapsulatedBean();
	
	/**
	 * The String representation of this bean for displaying in the cells
	 * within TreeTableView
	 * @return
	 */
	public abstract String getStringName();
	
	/**
	 * This method will act as a constructor for this. The method is necessary
	 * because the fields in the datamodel are initialized via reflection, thus
	 * fields that are not populated by reflection need to be initialized after
	 * that information is encapsulated 
	 * @return
	 */
	public abstract ProviderAttribute initialize();

}
