/*
 * LDAP Chai API
 * Copyright (c) 2006-2010 Novell, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package com.novell.ldapchai.impl.opendj.entry;

import com.novell.ldapchai.ChaiEntry;
import com.novell.ldapchai.ChaiPasswordPolicy;
import com.novell.ldapchai.ChaiPasswordRule;
import com.novell.ldapchai.exception.ChaiOperationException;
import com.novell.ldapchai.exception.ChaiUnavailableException;
import com.novell.ldapchai.provider.ChaiProvider;
import com.novell.ldapchai.util.ChaiLogger;
import com.novell.ldapchai.util.GenericRuleHelper;
import com.novell.ldapchai.util.PasswordRuleHelper;
import com.novell.ldapchai.util.SearchHelper;
import java.util.*;

/**
 * This class contains all the details of a password policy stored in OpenDJ.
 * 
 * @author Robert Meakins
 */
public class OpenDJPasswordPolicy extends TopImpl implements ChaiPasswordPolicy {
    private final Map<String, String> ruleMap = new HashMap<String, String>();
    private final Map<String, List<String>> allEntryValues = new HashMap<String, List<String>>();
    
    private static final ChaiLogger LOGGER = ChaiLogger.getLogger(OpenDJPasswordPolicy.class);
    
    public static final String LDAP_OBJECTCLASS_NAME = "pwdPolicy";
    public static final String MAX_PASSWORD_AGE_ATTR_NAME = "pwdMaxAge";
    public static final String VALIDATOR_ATTR_NAME = "ds-cfg-password-validator";
    public static final String VALIDATOR_ATTRIBUTE_VALUE_OBJECTCLASS_NAME = "ds-cfg-attribute-value-password-validator";
    public static final String VALIDATOR_CHARACTER_SET_OBJECTCLASS_NAME = "ds-cfg-character-set-password-validator";
    public static final String VALIDATOR_LENGTH_BASED_OBJECTCLASS_NAME = "ds-cfg-length-based-password-validator";
    public static final String VALIDATOR_REPEATED_CHARS_OBJECTCLASS_NAME = "ds-cfg-repeated-characters-password-validator";
    public static final String VALIDATOR_UNIQUE_CHARS_OBJECTCLASS_NAME = "ds-cfg-unique-characters-password-validator";
    public static final String VALIDATOR_MIN_LENGTH_ATTR_NAME = "ds-cfg-min-password-length";
    public static final String VALIDATOR_MAX_LENGTH_ATTR_NAME = "ds-cfg-max-password-length";
    public static final String VALIDATOR_MAX_CONSECUTIVE_LENGTH_ATTR_NAME = "ds-cfg-max-consecutive-length";
    public static final String VALIDATOR_MIN_UNIQUE_ATTR_NAME = "ds-cfg-min-unique-characters";
    public static final String VALIDATOR_MATCH_ATTRIBUTE_ATTR_NAME = "ds-cfg-match-attribute";
    public static final String VALIDATOR_CHARACTER_SET_ATTR_NAME = "ds-cfg-character-set";
    public static final String VALIDATOR_ALLOW_UNCLASSIFIED_ATTR_NAME = "ds-cfg-allow-unclassified-characters";
    public static final String LAST_LOGIN_TIME_ATTR_ATTR_NAME = "ds-cfg-last-login-time-attribute";
    public static final String LAST_LOGIN_TIME_FORMAT_ATTR_NAME = "ds-cfg-last-login-time-format";
        
    public OpenDJPasswordPolicy(final String entryDN, final ChaiProvider chaiProvider)
            throws ChaiUnavailableException, ChaiOperationException {
        super(entryDN, chaiProvider);
        
        getPasswordPolicyAttributes();
        setDefaultPolicyRules();
        readPasswordPolicyRules();
    }

    @Override
    public Set<String> getKeys() {
        return Collections.unmodifiableSet(ruleMap.keySet());
    }

    @Override
    public String getValue(final ChaiPasswordRule rule) {
        return ruleMap.get(rule.getKey());
    }

    @Override
    public String getValue(final String key) {
        return ruleMap.get(key);
    }

    @Override
    public String getLdapObjectClassName()
    {
        return LDAP_OBJECTCLASS_NAME;
    }
    
    @Override
    public PasswordRuleHelper getRuleHelper() {
        return new GenericRuleHelper(this);
    }

    @Override
    public final ChaiEntry getPolicyEntry() {
        return this;
    }
    
    private void getPasswordPolicyAttributes() throws ChaiUnavailableException, ChaiOperationException {
        
        //read all attribute values from entry.
        final SearchHelper searchHelper = new SearchHelper();
        searchHelper.setFilter(SearchHelper.DEFAULT_FILTER);
        searchHelper.setSearchScope(ChaiProvider.SEARCH_SCOPE.BASE);

        final Map<String, Map<String, List<String>>> bigResults = getChaiProvider().searchMultiValues(getEntryDN(), searchHelper);
        final Map<String, List<String>> results = bigResults.get(getEntryDN());

        allEntryValues.putAll(results);
    }
    
    private void setDefaultPolicyRules() {
        for (ChaiPasswordRule chaiPasswordRule : ChaiPasswordRule.values()) {
            ruleMap.put(chaiPasswordRule.getKey(), chaiPasswordRule.getDefaultValue());
        }
    }
    
    private void readPasswordPolicyRules() {
        
        // Get the ChaiPasswordRule.ExpirationInterval from the max password age
        // attribute on the password policy
        try {
            List<String> maxPasswordAgeList = allEntryValues.get(MAX_PASSWORD_AGE_ATTR_NAME);
            if (maxPasswordAgeList.size() == 1) {
                ruleMap.put(ChaiPasswordRule.ExpirationInterval.getKey(), maxPasswordAgeList.get(0));
            }
        } catch (Exception e) {
            LOGGER.error("error reading " + MAX_PASSWORD_AGE_ATTR_NAME + " to obtain ChaiPasswordRule.ExpirationInterval", e);
        }
    }
    
    public Map<ChaiPasswordRule, String> getPolicyRules() {
        final Map<ChaiPasswordRule, String> policyRules = new HashMap<ChaiPasswordRule, String>();
        
        for (String key : ruleMap.keySet()) {
            policyRules.put(ChaiPasswordRule.forKey(key), ruleMap.get(key));
        }
        
        return policyRules;
    }
    
    public void processValidators()
            throws ChaiUnavailableException, ChaiOperationException {
        List<String> validators = allEntryValues.get(VALIDATOR_ATTR_NAME);
        
        if (validators != null) {
            for (String validatorDn : validators) {
                // Get all attributes for the validator
                Map<String, List<String>> attrs = OpenDJEntries.getAllAttributesForDn(validatorDn, getChaiProvider());
                
                try {
                    if (attrs.get("objectClass").contains(VALIDATOR_ATTRIBUTE_VALUE_OBJECTCLASS_NAME)) {
                        
                        List<String> attrsToMatch = attrs.get(VALIDATOR_MATCH_ATTRIBUTE_ATTR_NAME);
                        StringBuilder disallowedAttrs = new StringBuilder();
                        for (String disallowedAttr : attrsToMatch) {
                            disallowedAttrs.append(disallowedAttr);
                            disallowedAttrs.append("\n");
                        }
                        ruleMap.put(ChaiPasswordRule.DisallowedAttributes.getKey(), disallowedAttrs.substring(0, disallowedAttrs.length() - 1));
                        
                    } else if (attrs.get("objectClass").contains(VALIDATOR_LENGTH_BASED_OBJECTCLASS_NAME)) {
                        
                        List<String> minLengthList = attrs.get(VALIDATOR_MIN_LENGTH_ATTR_NAME);
                        List<String> maxLengthList = attrs.get(VALIDATOR_MAX_LENGTH_ATTR_NAME);

                        if (minLengthList.size() == 1) {
                            ruleMap.put(ChaiPasswordRule.MinimumLength.getKey(), minLengthList.get(0));
                        }

                        if (maxLengthList.size() == 1) {
                            ruleMap.put(ChaiPasswordRule.MaximumLength.getKey(), maxLengthList.get(0));
                        }
                        
                    } else if (attrs.get("objectClass").contains(VALIDATOR_REPEATED_CHARS_OBJECTCLASS_NAME)) {
                        
                        List<String> repeatedCharsList = attrs.get(VALIDATOR_MAX_CONSECUTIVE_LENGTH_ATTR_NAME);
                        if (repeatedCharsList.size() == 1) {
                            ruleMap.put(ChaiPasswordRule.MaximumSequentialRepeat.getKey(), repeatedCharsList.get(0));
                        }
                        
                    } else if (attrs.get("objectClass").contains(VALIDATOR_UNIQUE_CHARS_OBJECTCLASS_NAME)) {
                        
                        List<String> uniqueCharsList = attrs.get(VALIDATOR_MIN_UNIQUE_ATTR_NAME);
                        if (uniqueCharsList.size() == 1) {
                            ruleMap.put(ChaiPasswordRule.MinimumUnique.getKey(), uniqueCharsList.get(0));
                        }
                        
                    } else if (attrs.get("objectClass").contains(VALIDATOR_CHARACTER_SET_OBJECTCLASS_NAME)) {
                        
                        // allowUnclassified - if false means that only chars
                        // defined in this validator may be used in passwords
                        boolean allowUnclassified = true;
                        List<String> allowUnclassifiedList = attrs.get(VALIDATOR_ALLOW_UNCLASSIFIED_ATTR_NAME);
                        if (allowUnclassifiedList.size() == 1 
                                && allowUnclassifiedList.get(0).equalsIgnoreCase("false")) {
                            allowUnclassified = false;
                            ruleMap.put(ChaiPasswordRule.AllowNumeric.getKey(), "false");
                            ruleMap.put(ChaiPasswordRule.AllowSpecial.getKey(), "false");
                        }
                        
                        List<String> characterSets = attrs.get(VALIDATOR_CHARACTER_SET_ATTR_NAME);
                        for (String characterSet : characterSets) {
                            String minChaiPasswordRule = null;
                            if (characterSet.contains("ABCD") || characterSet.contains("WXYZ")) { 
                                // Assume upper case
                                minChaiPasswordRule = ChaiPasswordRule.MinimumUpperCase.getKey();
                            } else if (characterSet.contains("abcd") || characterSet.contains("wxyz")) {
                                // Assume lower case
                                minChaiPasswordRule = ChaiPasswordRule.MinimumLowerCase.getKey();
                            } else if (characterSet.contains("1234")) {
                                // Assume numeric
                                minChaiPasswordRule = ChaiPasswordRule.MinimumNumeric.getKey();
                                ruleMap.put(ChaiPasswordRule.AllowNumeric.getKey(), "true");
                            } else if (characterSet.contains("()")) {
                                // Assume special
                                minChaiPasswordRule = ChaiPasswordRule.MinimumSpecial.getKey();
                                ruleMap.put(ChaiPasswordRule.AllowSpecial.getKey(), "true");
                            }
                            
                            // "Minimum" integer appears before the first colon
                            int colonIndex = characterSet.indexOf(":");
                            String minAllowed = characterSet.substring(0, colonIndex);
                            ruleMap.put(minChaiPasswordRule, minAllowed);
                        }
                    }
                } catch (Exception e) {
                    LOGGER.error("error while processing validators to obtain ChaiPasswordRules", e);
                }
                System.out.println(ruleMap);
            }
        }
    }
    
    public String getLastLoginTimeAttribute() {
        List<String> values = allEntryValues.get(LAST_LOGIN_TIME_ATTR_ATTR_NAME);
        if (values.size() == 1) {
            return values.get(0);
        }
            
        return null;
    }
    
    public String getLastLoginTimeFormat() {
        List<String> values = allEntryValues.get(LAST_LOGIN_TIME_FORMAT_ATTR_NAME);
        if (values.size() == 1) {
            return values.get(0);
        }
            
        return null;
    }
}
