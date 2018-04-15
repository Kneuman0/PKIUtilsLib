package fun.personalacademics.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentNameDictionary;
import org.apache.pdfbox.pdmodel.PDEmbeddedFilesNameTreeNode;
import org.apache.pdfbox.pdmodel.common.filespecification.PDComplexFileSpecification;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;

import fun.personalacademics.controllers.TrustListParsingController;
import fun.personalacademics.model.CertificateBean;

public class AATLParser extends TrustListParsingController {

	File xml;
	String fullFile;
	ArrayList<CertificateBean> certs;

	@Override
	public void initialize() {
		// TODO Auto-generated method stub

	}

	/**
	 * When initializing with this constructing - file must be the extracted AATL
	 * xml - not the PDF
	 * 
	 * @param xml
	 * @throws FileNotFoundException
	 */
	public AATLParser(File xml) throws FileNotFoundException {
		this.xml = xml;
		readCerts(new FileInputStream(xml));
	}

	/**
	 * When using this constructor, you must only use the Adobe AATL URLs that
	 * contains an XML attachment. Any other url will fail to parse.
	 * 
	 * @param aatl
	 * @throws InvalidPasswordException
	 * @throws IOException
	 */
	public AATLParser(URL aatl) throws InvalidPasswordException, IOException {
		PDDocument doc = PDDocument.load(aatl.openStream());

		PDDocumentNameDictionary names = new PDDocumentNameDictionary(doc.getDocumentCatalog());

		PDEmbeddedFilesNameTreeNode efTree = names.getEmbeddedFiles();

		Map<String, PDComplexFileSpecification> existedNames = null;

		existedNames = efTree.getNames();

		Set<String> attachments = existedNames.keySet();

		Iterator<String> itr = attachments.iterator();
		while (itr.hasNext()) {
			readCerts(existedNames.get(itr.next()).getEmbeddedFile().createInputStream());
		}
	}

	private void readCerts(InputStream stream) {
		certs = new ArrayList<CertificateBean>();

		Scanner scanner = new Scanner(stream);
		while (scanner.hasNext()) {
			String xmlLine = scanner.nextLine();
			String patternString = "<Certificate>[\\s\\S]*?<\\/Certificate>";
			Pattern pattern = Pattern.compile(patternString);
			Matcher matcher = pattern.matcher(xmlLine);
			while (matcher.find()) {
				String certB64 = xmlLine.substring(matcher.start(), matcher.end()).replace("<Certificate>", "")
						.replace("</Certificate>", "");
				CertificateBean cert = null;
				try {
					certs.addAll(convertBase64IntoCert(certB64));
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

			}

		}

		scanner.close();
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
