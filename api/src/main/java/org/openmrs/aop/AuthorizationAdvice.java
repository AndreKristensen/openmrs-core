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
package org.openmrs.aop;

import java.lang.reflect.Method;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.Iterator;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.User;
import org.openmrs.annotation.AuthorizedAnnotationAttributes;
import org.openmrs.api.APIAuthenticationException;
import org.openmrs.api.context.Context;
import org.springframework.aop.MethodBeforeAdvice;
import org.xacmlinfo.xacml.pep.agent.PEPAgent;
import org.xacmlinfo.xacml.pep.agent.PEPAgentException;
import org.xacmlinfo.xacml.pep.agent.PEPConfig;
import org.xacmlinfo.xacml.pep.agent.client.PEPClientConfig;

/**
 * This class provides the authorization AOP advice performed before every
 * service layer method call.
 */
public class AuthorizationAdvice implements MethodBeforeAdvice {

	/**
	 * Logger for this class and subclasses
	 */
	protected final Log log = LogFactory.getLog(AuthorizationAdvice.class);

	PEPAgent pepAgent = null;

	public AuthorizationAdvice() {
		try {
			PEPConfig pepConfig = new PEPConfig();
			PEPClientConfig clientConfig = new PEPClientConfig();
			clientConfig.setServerHostName("localhost");
			clientConfig.setServerPort("9443");
			clientConfig.setServerUserName("admin");
			clientConfig.setServerPassword("admin");
			// URI uri = new URI();

			clientConfig.setTrustStoreFile("C:\\utvikling\\wso2is-5.0.0\\repository\\resources\\security\\client-truststore.jks");
			clientConfig.setTrustStorePassword("wso2carbon");
			pepConfig.setPepClientConfig(clientConfig);

			pepAgent = PEPAgent.getInstance(pepConfig);
		} catch (PEPAgentException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Allows us to check whether a user is authorized to access a particular
	 * method.
	 *
	 * @param method
	 * @param args
	 * @param target
	 * @throws Throwable
	 * @should notify listeners about checked privileges
	 */
	@SuppressWarnings({ "unchecked" })
	public void before(Method method, Object[] args, Object target) throws Throwable {
		User user = Context.getAuthenticatedUser();
		
		String action = null;
		String userName = null;

		if (log.isDebugEnabled()) {
			log.debug("Calling authorization advice before " + method.getName());
		}

		if (log.isDebugEnabled()) {
			log.debug("User " + user);
			if (user != null) {
				log.debug("has roles " + user.getAllRoles());
			}
		}

		AuthorizedAnnotationAttributes attributes = new AuthorizedAnnotationAttributes();
		Collection<String> privileges = attributes.getAttributes(method);
		boolean requireAll = attributes.getRequireAll(method);

		// Only execute if the "secure" method has authorization attributes
		// Iterate through required privileges and return only if the user has
		// one of them
		if (!privileges.isEmpty()) {
			System.out.println(method.getName());
			System.out.println(privileges.toString() + " reqiuer all " + requireAll);
			
			for (String privilege : privileges) {

				
				// skip null privileges
				if (privilege == null || privilege.isEmpty()) {
					return;
				}
				
				if (pepAgent != null && user != null) {
					
					String subjecId = user.getUserId().toString();
					String resource = "openmrs-patient";
					String decision = pepAgent.getDecision(
							"<Request xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\" CombinedDecision=\"false\" ReturnPolicyIdList=\"false\">" + 
									"<Attributes Category=\"urn:oasis:names:tc:xacml:3.0:attribute-category:action\">" +
									"<Attribute AttributeId=\"urn:oasis:names:tc:xacml:1.0:action:action-id\" IncludeInResult=\"true\">" +
									"<AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">"+privilege+"</AttributeValue>" + 
									"</Attribute>" +
									"</Attributes>" +
									"<Attributes Category=\"urn:oasis:names:tc:xacml:1.0:subject-category:access-subject\">" + 
									"<Attribute AttributeId=\"urn:oasis:names:tc:xacml:1.0:subject:subject-id\" IncludeInResult=\"false\">" +
									"<AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">"+subjecId+"</AttributeValue>" + 
									"</Attribute>" + 
									"</Attributes>" + 
									"<Attributes Category=\"urn:oasis:names:tc:xacml:3.0:attribute-category:resource\">"+ 
									"<Attribute AttributeId=\"urn:oasis:names:tc:xacml:1.0:resource:resource-id\" IncludeInResult=\"false\">" + 
									"<AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">"+resource+"</AttributeValue>"+ 
									"</Attribute>" + 
									"</Attributes>" + 
									"</Request>");

					  OMElement omElement = AXIOMUtil.stringToOM(decision);
					  
					  
					  Iterator iterator = omElement.getChildElements();
			            while(iterator.hasNext()){
			                OMElement element = (OMElement) iterator.next();
			                if("Result".equals(element.getLocalName())){
			                    String result = element.toString();
			                    System.out.println(result);
//			                    if(result.contains("Permit")){
//			                    	
//			                        
//			                    }
			                }
			            }
			            
					 System.out.println(decision.contains("Permit"));
				}

				if (log.isDebugEnabled()) {
					log.debug("User has privilege " + privilege + "? " + Context.hasPrivilege(privilege));
				}

				if (Context.hasPrivilege(privilege)) {
					if (!requireAll) {
						// if not all required, the first one that they have
						// causes them to "pass"
						return;
					}
				} else {
					if (requireAll) {
						// if all are required, the first miss causes them
						// to "fail"
						throwUnauthorized(user, method, privilege);
					}
				}
			}

			if (requireAll == false) {
				// If there's no match, then we know there are privileges and
				// that the user didn't have any of them. The user is not
				// authorized to access the method
				throwUnauthorized(user, method, privileges);
			}

		} else if (attributes.hasAuthorizedAnnotation(method)) {
			// if there are no privileges defined, just require that
			// the user be authenticated
			if (Context.isAuthenticated() == false) {
				throwUnauthorized(user, method);
			}
		}
	}

	/**
	 * Throws an APIAuthorization exception stating why the user failed
	 *
	 * @param user
	 *            authenticated user
	 * @param method
	 *            acting method
	 * @param attrs
	 *            Collection of String privilege names that the user must have
	 */
	private void throwUnauthorized(User user, Method method, Collection<String> attrs) {
		if (log.isDebugEnabled()) {
			log.debug("User " + user + " is not authorized to access " + method.getName());
		}
		throw new APIAuthenticationException(Context.getMessageSourceService().getMessage("error.privilegesRequired", new Object[] { StringUtils.join(attrs, ",") }, null));
	}

	/**
	 * Throws an APIAuthorization exception stating why the user failed
	 *
	 * @param user
	 *            authenticated user
	 * @param method
	 *            acting method
	 * @param attrs
	 *            privilege names that the user must have
	 */
	private void throwUnauthorized(User user, Method method, String attr) {
		if (log.isDebugEnabled()) {
			log.debug("User " + user + " is not authorized to access " + method.getName());
		}
		throw new APIAuthenticationException(Context.getMessageSourceService().getMessage("error.privilegesRequired", new Object[] { attr }, null));
	}

	/**
	 * Throws an APIAuthorization exception stating why the user failed
	 *
	 * @param user
	 *            authenticated user
	 * @param method
	 *            acting method
	 */
	private void throwUnauthorized(User user, Method method) {
		if (log.isDebugEnabled()) {
			log.debug("User " + user + " is not authorized to access " + method.getName());
		}
		throw new APIAuthenticationException(Context.getMessageSourceService().getMessage("error.aunthenticationRequired"));
	}
}
