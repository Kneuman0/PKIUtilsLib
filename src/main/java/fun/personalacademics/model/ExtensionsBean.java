package fun.personalacademics.model;

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
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.PolicyMappings;
import org.bouncycastle.asn1.x509.TBSCertificate;

import fun.personalacademics.utils.CertificateUtilities;


public class ExtensionsBean {
	
	private Extensions exts;
	
	public ExtensionsBean(X509Certificate cert) throws CertificateEncodingException{
		exts = TBSCertificate.getInstance(ASN1Sequence.getInstance(cert.getEncoded()).getObjectAt(0)).getExtensions();
	}
	
	@Override
	public String toString(){
		String value = "";
		List<ASN1ObjectIdentifier> list = new ArrayList<>(Arrays.asList());
		list.addAll(Arrays.asList());
		value += "----Critical Extensions----";
		for(ASN1ObjectIdentifier id : exts.getCriticalExtensionOIDs()){
			value += "\nOID: " + id.getId() + "=:: " + CertificateUtilities.getExtensionDesc(id.getId());
			try {
				value += "\nValue: " + getExtenstionValue(id);
			} catch (CertificateParsingException e) {
				value += "\nError: " + e.getMessage();
				System.err.println(e.getMessage());
			}
		}
		value += "\n----Critical Extensions----\n";
		value += "\n----Non-Critical Extensions----";
		for(ASN1ObjectIdentifier id : exts.getNonCriticalExtensionOIDs()){
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
		}else{
			value += exts.getExtension(oid).getParsedValue().toString();
		}
		
		return value;
	}
	
	public AuthorityInfoAccess getAuthorityInfoAccess() throws CertificateParsingException{
		AuthorityInfoAccess aia = null;
		try {
			aia = new AuthorityInfoAccess(
					(ASN1Sequence)exts.getExtension(Extension.authorityInfoAccess).getParsedValue());
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
			crlPnt = CRLDistPoint.getInstance(exts.getExtensionParsedValue(Extension.cRLDistributionPoints));
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
			bc = BasicConstraints.getInstance(exts.getExtension(Extension.basicConstraints));
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
			crlr = CRLNumber.getInstance(exts.getExtension(Extension.cRLNumber));
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
			pm = PolicyMappings.getInstance(exts.getExtension(Extension.policyMappings));
		} catch (Exception e) {
			throw new CertificateParsingException(
					"Either the Policy Mappings do not exist or could not be parsed"
					+ " and/or Error:\n" + e.getMessage());
		}
		
		return pm;
	}
	
	
}
