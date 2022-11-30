package fr.paris.lutece.util.signrequest;

import java.util.HashMap;
import java.util.Map;


/**
 * The Class AuthenticateRequestInformations.
 */
public class AuthenticateRequestInformations {
	
	/** The security headers. */
	private Map<String,String> _securityHeaders=new HashMap<String, String>();
	
	/** The security parameters. */
	private Map<String,String> _securityParameters=new HashMap<String, String>();
	
	
	/**
	 * Gets the security headers.
	 *
	 * @return the security headers
	 */
	public Map<String,String> getSecurityHeaders()
	{
		return _securityHeaders;
	}

	/**
	 * Gets the security parameteres.
	 *
	 * @return the security parameteres
	 */
	public Map<String,String> getSecurityParameteres()
	{
		return _securityParameters;
	}
	
	
	/**
	 * Adds the security parameter.
	 *
	 * @param strParam the str param
	 * @param strValue the str value
	 * @return the authenticate request informations
	 */
	public  AuthenticateRequestInformations addSecurityParameter(String strParam,String strValue)
	{
		_securityParameters.put(strParam, strValue);
		return  this;
	}
	
	/**
	 * Adds the security header.
	 *
	 * @param strParam the str param
	 * @param strValue the str value
	 * @return the authenticate request informations
	 */
	public  AuthenticateRequestInformations  addSecurityHeader(String strParam,String strValue)
	{
		_securityHeaders.put(strParam, strValue);
		return  this;
	}
	
	
	
	
	
}
