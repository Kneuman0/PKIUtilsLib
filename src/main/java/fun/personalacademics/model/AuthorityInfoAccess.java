package fun.personalacademics.model;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.GeneralName;

public class AuthorityInfoAccess {
	
	private AuthorityInformationAccess aia;
	
	public AuthorityInfoAccess(ASN1Sequence seq) {
		this.aia = AuthorityInformationAccess.getInstance(seq);
	}
	
	public List<String> getLocations(){
		List<String> locations = new ArrayList<>();
		for(AccessDescription accdesc : aia.getAccessDescriptions()){
			locations.add(DERIA5String.getInstance(accdesc.getAccessLocation().getName()).getString());
		}
		
		return locations;
	}
	
	public AuthorityInformationAccess getBCAuthorityInformationAccess(){
		return aia;
	}
	
	public String toString(){
		String value = "";
		value += "Locations: " + getLocations();
		return value;
	}

}
