package fun.personalacademics.model;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import fun.personalacademics.controllers.TrustListParsingController;
import fun.personalacademics.utils.CertificateEncapsulater;
import fun.personalacademics.utils.CertificateEncapsulater.CERT_TYPES;

public class AATLParser extends TrustListParsingController{
	
	File xml;
	String fullFile;
	ArrayList<CertificateBean> certs;
	@Override
	public void initialize() {
		// TODO Auto-generated method stub
		
	}
	
	public AATLParser(File file) throws FileNotFoundException {
		this.xml = file;
		certs = new ArrayList<CertificateBean>();
		
		Scanner scanner = new Scanner(new FileInputStream(file));
		while(scanner.hasNext()) {
			String xmlLine = scanner.nextLine();
			String patternString = "<Certificate>[\\s\\S]*?<\\/Certificate>";
			Pattern pattern = Pattern.compile(patternString);
			Matcher matcher = pattern.matcher(xmlLine);
			while(matcher.find()) {
				String certB64 = xmlLine.substring(matcher.start(), matcher.end())
						.replace("<Certificate>", "").replace("</Certificate>", "");
				CertificateBean cert = null;
				try {
					certs.addAll(convertBase64IntoCert(certB64));
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
			}
			
		}
		
	}

	public File getXml() {
		return xml;
	}

	public void setXml(File xml) {
		this.xml = xml;
	}

	public String getFullFile() {
		return fullFile;
	}

	public void setFullFile(String fullFile) {
		this.fullFile = fullFile;
	}

	public ArrayList<CertificateBean> getCerts() {
		return certs;
	}

	public void setCerts(ArrayList<CertificateBean> certs) {
		this.certs = certs;
	}
	
	

}
