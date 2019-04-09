package fun.personalacademics.model;

import java.security.cert.X509Certificate;
import java.util.List;

public interface CertNode {
	
	List<X509Certificate> certChain();
	
	X509Certificate getNodeCert();
	
	X509Certificate setNodeCert();
	
	String nodeSubject();
	
	String nodeIssuer();
	
	X509Certificate getIssuerCertificate();
	
	

}
