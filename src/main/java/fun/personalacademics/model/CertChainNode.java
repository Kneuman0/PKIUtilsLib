package fun.personalacademics.model;

import java.security.cert.X509Certificate;
import java.util.List;


public abstract class CertChainNode implements CertNode{
	

	protected List<X509Certificate> certChain;
	
	protected X509Certificate nodeCert;
	
	protected X509Certificate issuerCertificate;
	
	protected String subject;
	
	protected String issuer;
	

	@Override
	public List<X509Certificate> certChain() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public X509Certificate getNodeCert() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public X509Certificate setNodeCert() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String nodeSubject() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String nodeIssuer() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public X509Certificate getIssuerCertificate() {
		// TODO Auto-generated method stub
		return null;
	}

}
