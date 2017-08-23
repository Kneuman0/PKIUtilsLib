package fun.personalacademics.model;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;

import fun.personalacademics.utils.CertificateUtilities;
import fun.personalacademics.utils.RadixConverter;
import fun.personalacademics.model.ProviderAttribute;
import javafx.beans.property.SimpleObjectProperty;

public class CertificateBean extends ProviderAttribute {

	private X509Certificate parentCert;
	private SimpleObjectProperty<CertificateBean> name;
	private String stringName;
	private List<CertificateBean> childrenCerts;
	private ProviderAttributeType type;

	public CertificateBean() {
		this.type = ProviderAttributeType.CERTIFICATE_BEAN;
		childrenCerts = new ArrayList<>();
		name = new SimpleObjectProperty<CertificateBean>(this);
		stringName = "Empty";
	}

	public CertificateBean(byte[] binary) throws CertificateException {
		CertificateFactory fact = CertificateFactory.getInstance("X.509");
		ByteArrayInputStream input = new ByteArrayInputStream(binary);
		parentCert = (X509Certificate) fact.generateCertificate(input);

		this.type = ProviderAttributeType.CERTIFICATE_BEAN;
		this.name = new SimpleObjectProperty<CertificateBean>(this);

		Map<String, String> attr = new HashMap<String, String>();
		for (String pair : parentCert.getSubjectDN().toString().split(",")) {
			String[] attributes = pair.split("=");
			if (attributes.length == 2)
				attr.put(attributes[0].trim(), attributes[1].trim());
		}
		this.stringName = attr.get("CN") != null ? attr.get("CN") : attr.get("OU");
	}

	public CertificateBean(CertificateBean bean) {
		this.type = ProviderAttributeType.CERTIFICATE_BEAN;
		this.parentCert = bean.getParentCert();
		this.name = bean.getName();
		this.stringName = bean.getStringName();
		this.childrenCerts = bean.getChildrenCerts();
	}

	// cheap way to get root node
	public CertificateBean(String name) {
		this.type = ProviderAttributeType.CERTIFICATE_BEAN;
		this.stringName = name;
		this.name = new SimpleObjectProperty<CertificateBean>(this);
	}

	public CertificateBean(X509Certificate parent, List<X509Certificate> children) {
		this.type = ProviderAttributeType.CERTIFICATE_BEAN;
		this.name = new SimpleObjectProperty<CertificateBean>(this);
		childrenCerts = new ArrayList<>();
		if (children != null) {
			for (X509Certificate cert : children)
				childrenCerts.add(new CertificateBean(cert));
		}

		Map<String, String> attr = new HashMap<String, String>();
		for (String pair : parent.getSubjectDN().toString().split(",")) {
			String[] attributes = pair.split("=");
			if (attributes.length == 2)
				attr.put(attributes[0].trim(), attributes[1].trim());
		}
		this.stringName = attr.get("CN") != null ? attr.get("CN") : attr.get("OU");

		this.parentCert = parent;
	}

	public CertificateBean(X509Certificate cert) {
		this.type = ProviderAttributeType.CERTIFICATE_BEAN;
		this.name = new SimpleObjectProperty<CertificateBean>(this);
		parentCert = cert;
		childrenCerts = new ArrayList<>();
		Map<String, String> attr = new HashMap<String, String>();
		for (String pair : cert.getSubjectDN().toString().split(",")) {
			String[] attributes = pair.split("=");
			if (attributes.length == 2)
				attr.put(attributes[0].trim(), attributes[1].trim());
		}
		name = new SimpleObjectProperty<CertificateBean>(this);

		this.stringName = attr.get("CN") != null ? attr.get("CN") : attr.get("OU");
	}

	/**
	 * @return the parentCert
	 */
	public X509Certificate getParentCert() {
		return parentCert;
	}

	/**
	 * @param parentCert
	 *            the parentCert to set
	 */
	public void setParentCert(X509Certificate parentCert) {
		this.parentCert = parentCert;
	}

	/**
	 * @return the childrenCerts
	 */
	public List<CertificateBean> getChildrenCerts() {
		return childrenCerts;
	}

	/**
	 * @param childrenCerts
	 *            the childrenCerts to set
	 */
	public void setChildrenCerts(List<CertificateBean> childrenCerts) {
		this.childrenCerts = childrenCerts;
	}

	/**
	 * @return the name
	 */
	public SimpleObjectProperty<CertificateBean> getName() {
		return name;
	}

	/**
	 * @param name
	 *            the name to set
	 */
	public void setName(String name) {
		this.name = new SimpleObjectProperty<CertificateBean>(this);
	}

	/**
	 * @param name
	 *            the name to set
	 */
	public void setName(CertificateBean name) {
		this.name = new SimpleObjectProperty<CertificateBean>(name);
	}

	public SimpleObjectProperty<ProviderAttribute> nameProperty() {
		return new SimpleObjectProperty<ProviderAttribute>(this);
	}

	/**
	 * @param type
	 *            the type to set
	 */
	public void setType(ProviderAttributeType type) {
		this.type = type;
	}

	public String getBase64Parent() {
		try {
			return DatatypeConverter.printBase64Binary(parentCert.getEncoded());
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
			return "Error with cert";
		}
	}

	public String getX509SKI() {
		return CertificateUtilities.generateX509SKI(parentCert);
	}

	public String getThumbprint() throws CertificateEncodingException {
		return CertificateUtilities.generateCertThumbprint(parentCert);
	}

	public String toString() {
		if (parentCert == null)
			return "";

		StringBuilder builder = new StringBuilder();
		builder.append("Version: " + parentCert.getVersion());
		builder.append("\nSerial Number: " + parentCert.getSerialNumber());
		builder.append("\nStart Date: " + parentCert.getNotBefore());
		builder.append("\nEnd Date: " + parentCert.getNotAfter());
		builder.append("\nIssuer: " + parentCert.getIssuerX500Principal().toString());
		builder.append("\nSubject: " + parentCert.getSubjectX500Principal().toString());
		builder.append("\nAlgorithm: " + parentCert.getSigAlgName());
		builder.append("\nOIDs: " + parentCert.getCriticalExtensionOIDs());
		builder.append("\n\n------Public Key ------");
		builder.append("\n" + parentCert.getPublicKey());
		builder.append("\nBit String: " + CertificateUtilities.generatePublicKeyString(parentCert));
		builder.append("\nSubjectPublicKeyInfo: " + CertificateUtilities.getHexASN1SubjectPubKeyInfo(parentCert));
		builder.append("\n-----Public Key-----");
		builder.append("\n\n-----Extensions-----");
//		builder.append("\nCritical: " + getCriticalExtensions());
//		builder.append("\nNon Critical: " + getNonCriticalExtensions());
		builder.append("\n" + printExtensions());
		builder.append("\n-----Extensions-----\n");
		builder.append("\nKey Usages: " + getKeyUsages());
	
		try {
			builder.append("\nExtended Key Usages: " + parentCert.getExtendedKeyUsage());
			builder.append("\n\nX509SKI: " + getX509SKI());
			builder.append("\nThumbprint: " + getThumbprint());
			builder.append("\n\nBase64Encoded: " + DatatypeConverter.printBase64Binary(parentCert.getEncoded()));
		} catch (CertificateParsingException e) {
			e.printStackTrace();
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		}
		
		builder.append("\nSignature: " + getSignature());

		return builder.toString();
	}

	/**
	 * @return the stringName
	 */
	public String getStringName() {
		return stringName;
	}

	/**
	 * @param stringName
	 *            the stringName to set
	 */
	public void setStringName(String stringName) {
		this.stringName = stringName;
	}

	/**
	 * Checks if the two object are equal by getting the parent certificates and
	 * comparing their serial numbers
	 */
	@Override
	public boolean equals(Object object) {
		if (object instanceof CertificateBean) {
			CertificateBean bean = (CertificateBean) object;
			boolean equal = false;
			try {
				equal = bean.getThumbprint().equals(this.getThumbprint());
			} catch (CertificateEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return equal;
		} else {
			return false;
		}

	}

	@Override
	public ProviderAttributeType getType() {

		return type;
	}

	/**
	 * Use of this method assumed a check has been placed using the getType()
	 * first to determine the Type of this subclass
	 */
	@SuppressWarnings("unchecked")
	@Override
	public CertificateBean getEncapsulatedBean() {

		return this;
	}

	@Override
	public ProviderAttribute initialize() {
		// deliberately empty method
		return this;
	}

	public ArrayList<String> getKeyUsages() {
		ArrayList<String> keyUsages = new ArrayList<>();
		boolean[] parentKeyUsage = parentCert.getKeyUsage();

		if (parentKeyUsage[0]) {
			keyUsages.add("CERT_SIGN");
		}

		if (parentKeyUsage[1]) {
			keyUsages.add("CRL_SIGN");
		}

		if (parentKeyUsage[2]) {
			keyUsages.add("DATA_ENCIPHERMENT");
		}

		if (parentKeyUsage[3]) {
			keyUsages.add("DIGITAL_SIGNATURE");
		}

		if (parentKeyUsage[4]) {
			keyUsages.add("GOVT_APPROVED");
		}

		if (parentKeyUsage[5]) {
			keyUsages.add("KEY_AGREEMENT");
		}

		if (parentKeyUsage[6]) {
			keyUsages.add("KEY_ENCIPHERMENT");
		}

		if (parentKeyUsage[7]) {
			keyUsages.add("NON_REPUDIATION");
		}

		return keyUsages;

	}

	public String getCriticalExtensions() {
		Set<String> critSet = parentCert.getCriticalExtensionOIDs();
		return new ArrayList<String>(critSet).toString();
	}
	
	public String getNonCriticalExtensions(){
		Set<String> nonCritSet = parentCert.getNonCriticalExtensionOIDs();
		return new ArrayList<String>(nonCritSet).toString();
	}
	
	public String printExtensions(){
		String value = "";
		try {
			value = new ExtensionsBean(getParentCert()).toString();
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		}
		
		return value;
	}
	
	public String getSignature(){
		return RadixConverter.binaryTextToHex(parentCert.getSignature());
	}
	
	public String getParameters(){
		return RadixConverter.binaryToASCII(
				parentCert.getExtensionValue(Extension.authorityKeyIdentifier.getId()));
	}
	
	public ExtensionsBean getExtensions() throws CertificateEncodingException{
		return new ExtensionsBean(getParentCert());
	}
	
	
	
	

}
