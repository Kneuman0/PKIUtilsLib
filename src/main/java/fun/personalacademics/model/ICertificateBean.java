package fun.personalacademics.model;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import com.zeva.tlgen.dataModel.ProviderAttribute;

import javafx.beans.property.SimpleObjectProperty;

@SuppressWarnings("restriction")
public interface ICertificateBean {
	
	/**
	 * @return the parentCert
	 */
	public X509Certificate getParentCert();

	/**
	 * @param parentCert
	 *            the parentCert to set
	 */
	public void setParentCert(X509Certificate parentCert);

	/**
	 * @return the childrenCerts
	 */
	public List<CertificateBean> getChildrenCerts();
	
	/**
	 * @param childrenCerts
	 *            the childrenCerts to set
	 */
	public void setChildrenCerts(List<CertificateBean> childrenCerts);

	/**
	 * @return the name
	 */
	public SimpleObjectProperty<CertificateBean> getName();

	/**
	 * @param name
	 *            the name to set
	 */
	public void setName(String name);

	/**
	 * @param name
	 *            the name to set
	 */
	public void setName(CertificateBean name);

	public SimpleObjectProperty<ProviderAttribute> nameProperty();

	public String getBase64Parent();

	public String getX509SKI();

	public String getThumbprint() throws CertificateEncodingException ;


	/**
	 * @return the stringName
	 */
	public String getStringName() ;

	/**
	 * @param stringName
	 *            the stringName to set
	 */
	public void setStringName(String stringName);


	public ArrayList<String> getKeyUsages();

	public String getCriticalExtensions() ;
	
	public String getNonCriticalExtensions();
	
	public String printExtensions();
	
	public String getSignature();
	
	public String getParameters();
	
	public ExtensionsBean getExtensions() throws CertificateEncodingException, IOException;
	
	
	
}
