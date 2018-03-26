package fun.personalacademics.model;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyMappings;
import org.bouncycastle.cert.X509CertificateHolder;

import fun.personalacademics.utils.CertificateUtilities;


public class ExtensionsBean extends X509CertificateHolder{
	
	public ExtensionsBean(X509Certificate cert) throws IOException, CertificateEncodingException{
		super(cert.getEncoded());
	}
	
	@Override
	public String toString(){
		String value = "";
		List<ASN1ObjectIdentifier> list = new ArrayList<>(Arrays.asList());
		list.addAll(Arrays.asList());
		value += "----Critical Extensions----";
		for(ASN1ObjectIdentifier id : getExtensions().getCriticalExtensionOIDs()){
			value += "\nOID: " + id.getId() + "=:: " + CertificateUtilities.getExtensionDesc(id.getId());

			try {
				value += "\nValue: " + getExtenstionValue(id);
			} catch (CertificateParsingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
		value += "\n----Critical Extensions----\n";
		value += "\n----Non-Critical Extensions----";
		for(ASN1ObjectIdentifier id : getExtensions().getNonCriticalExtensionOIDs()){
			value += "\nOID: " + id.getId() + "=:: " + CertificateUtilities.getExtensionDesc(id.getId());
			try {
				value += "\nValue: " + getExtenstionValue(id);
			} catch (CertificateParsingException e) {
				value += "\nError: " + e.getMessage();
				System.err.println(e.getMessage());
			}
		}
		value += "\n----Non-Critical Extensions----\n\n";
		
		return value;
	}
	
	public String getExtenstionValue(ASN1ObjectIdentifier oid) throws CertificateParsingException{
		String value = "";
		if(oid.getId().equals(Extension.authorityInfoAccess.getId())){
			value += getAuthorityInfoAccess().toString();	
		}else if(oid.getId().equals(Extension.cRLDistributionPoints.getId())){
			value += getCRLDistPoints().toString();
		}else if(oid.getId().equals(Extension.policyMappings.getId())){
			value += getPolicyMappings().toString();
		}else if(oid.getId().equals(Extension.cRLNumber.getId())){
			value += getCRLNumber().getCRLNumber().toString();
		}else if(oid.getId().equals(Extension.keyUsage.getId())){
			value += getKeyUsage().toString();
		}else if(oid.getId().equals(Extension.basicConstraints.getId())){
			value += getCRLNumber().getCRLNumber().toString();
		}else{
			value += getExtensions().getExtension(oid).getParsedValue().toString();
		}
		
		return value;
	}
	
	public AuthorityInfoAccess getAuthorityInfoAccess() throws CertificateParsingException{
		AuthorityInfoAccess aia = null;
		try {
			aia = new AuthorityInfoAccess(
					(ASN1Sequence)getExtensions().getExtension(Extension.authorityInfoAccess).getParsedValue());
		} catch (Exception e) {
			throw new CertificateParsingException(
					"Either the Authority Info Access points do not exist or could not be parsed"
					+ " and/or Error:\n" + e.getMessage());
		}
		
		return aia;
	}
	
	public CRLDistPoint getCRLDistPoints() throws CertificateParsingException{
		CRLDistPoint crlPnt = null;
		try {
			crlPnt = CRLDistPoint.getInstance(getExtensions().getExtensionParsedValue(Extension.cRLDistributionPoints));
		} catch (Exception e) {
			throw new CertificateParsingException(
					"Either the CRL dist. points do not exist or could not be parsed"
					+ " and/or Error:\n" + e.getMessage());
		}
		return crlPnt != null ? crlPnt : null;
	}
	
	public BasicConstraints getBasicConstraints() throws CertificateParsingException{
		BasicConstraints bc = null;
		try {
			bc = BasicConstraints.getInstance(getExtensions().getExtension(Extension.basicConstraints));
		} catch (Exception e) {
			throw new CertificateParsingException(
					"Either the Basic Constraints do not exist or could not be parsed"
					+ " and/or Error:\n" + e.getMessage());
		}
		
		return bc;
	}
	
	public CRLNumber getCRLNumber() throws CertificateParsingException{
		CRLNumber crlr = null;
		try {
			crlr = CRLNumber.getInstance(getExtensions().getExtension(Extension.cRLNumber));
		} catch (Exception e) {
			throw new CertificateParsingException(
					"Either the CRL Reason does not exist or could not be parsed"
					+ " and/or Error:\n" + e.getMessage());
		}
		
		return crlr;
	}
	
	public PolicyMappings getPolicyMappings() throws CertificateParsingException{
		PolicyMappings pm = null;
		try {
			pm = PolicyMappings.getInstance(getExtensions().getExtension(Extension.policyMappings));
		} catch (Exception e) {
			throw new CertificateParsingException(
					"Either the Policy Mappings do not exist or could not be parsed"
					+ " and/or Error:\n" + e.getMessage());
		}
		
		return pm;
	}
	
	public List<String> getKeyUsage() throws CertificateParsingException{
		List<String> keyUsage = null;
		try {
			keyUsage = new CertificateBean(super.getEncoded()).getKeyUsages();
		} catch (Exception e) {
			throw new CertificateParsingException(
					"Either the Key Usage do not exist or could not be parsed"
					+ " and/or Error:\n" + e.getMessage());
		}
		
		return keyUsage;
	}
	

	
}
