/**
 * The contents of this file are subject to the OpenMRS Public License
 * Version 1.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://license.openmrs.org
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 * License for the specific language governing rights and limitations
 * under the License.
 *
 * Copyright (C) OpenMRS, LLC.  All Rights Reserved.
 */
package org.openmrs.web.taglib;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.servlet.jsp.tagext.TagSupport;
import javax.xml.stream.XMLStreamException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.User;
import org.openmrs.api.context.Context;
import org.openmrs.api.context.UserContext;
import org.xacmlinfo.xacml.pep.agent.PEPAgentException;

import no.ask.xacml.util.XACMLCommunication;

public class PrivilegeTag extends TagSupport {
	
	public static final long serialVersionUID = 11233L;
	
	private final Log log = LogFactory.getLog(getClass());
	
	private String privilege;
	
	private String inverse;

	private XACMLCommunication pep = null;
	
	public PrivilegeTag() {
		try {
			pep = new XACMLCommunication("localhost", "9443", "admin", "admin", "C:\\utvikling\\wso2is-5.0.0\\repository\\resources\\security\\client-truststore.jks", "wso2carbon");
		} catch (PEPAgentException e) {
			e.printStackTrace();
		}
    }
	
	public int doStartTag() {
		
//		User user = Context.getAuthenticatedUser();
		UserContext userContext = Context.getUserContext();
		
		
		log.debug("Checking user " + userContext.getAuthenticatedUser() + " for privs " + privilege);
		
		boolean hasPrivilege = false;
		Collection<String> privileges = new ArrayList<String>();
		if (privilege.contains(",")) {
			String[] privs = privilege.split(",");
			for (String p : privs) {
				privileges.add(p);
				if (userContext.hasPrivilege(p)) {
					hasPrivilege = true;
					break;
				}
			}
		} else {
			privileges.add(privilege);
			hasPrivilege = userContext.hasPrivilege(privilege);
		}
		
		User authenticatedUser = userContext.getAuthenticatedUser();
		
		try {
			if(authenticatedUser != null){
				// allow inversing
				
				System.out.println(privileges);
				List<String> decisonResults = pep.getDecisonResults(authenticatedUser.getId().toString(), privileges , "openmrs.com",null);
				System.out.println(decisonResults.toString());
				
				
				boolean isInverted = false;
				if (inverse != null) {
					isInverted = "true".equals(inverse.toLowerCase());
				}
				
				boolean b = decisonResults.get(0).equals(XACMLCommunication.RESULT_PERMIT) && !isInverted;
				boolean c = decisonResults.get(0).equals(XACMLCommunication.RESULT_DENY) && isInverted;
				if (b || c) {
					pageContext.setAttribute("authenticatedUser", userContext.getAuthenticatedUser());
					return EVAL_BODY_INCLUDE;
				} else {
					return SKIP_BODY;
				}
			
			}
        } catch (NullPointerException e) {
	        // TODO Auto-generated catch block
	        e.printStackTrace();
        } catch (PEPAgentException e) {
	        // TODO Auto-generated catch block
	        e.printStackTrace();
        } catch (XMLStreamException e) {
	        // TODO Auto-generated catch block
	        e.printStackTrace();
        }
		
		// allow inversing
		boolean isInverted = false;
		if (inverse != null) {
			isInverted = "true".equals(inverse.toLowerCase());
		}
		
		if ((hasPrivilege && !isInverted) || (!hasPrivilege && isInverted)) {
			pageContext.setAttribute("authenticatedUser", userContext.getAuthenticatedUser());
			return EVAL_BODY_INCLUDE;
		} else {
			return SKIP_BODY;
		}
	}
	
	/**
	 * @return Returns the privilege.
	 */
	public String getPrivilege() {
		return privilege;
	}
	
	/**
	 * @param converse The privilege to set.
	 */
	public void setPrivilege(String privilege) {
		this.privilege = privilege;
	}
	
	/**
	 * @return Returns the inverse.
	 */
	public String getInverse() {
		return inverse;
	}
	
	/**
	 * @param inverse The inverse to set.
	 */
	public void setInverse(String inverse) {
		this.inverse = inverse;
	}
}
