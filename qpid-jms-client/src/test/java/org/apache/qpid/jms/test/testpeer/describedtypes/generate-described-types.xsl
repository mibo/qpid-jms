<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"
                xmlns:exsl="http://exslt.org/common"
                extension-element-prefixes="exsl">

<!-- Used to generate the Java classes in this package.
     Changes to these classes should be effected by modifying this stylesheet then re-running it,
     using a stylesheet processor that understands the exsl directives such as xsltproc -->

<xsl:template match="/">
    <xsl:variable name="license">/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */
</xsl:variable>

    <xsl:for-each select="descendant-or-self::node()[name()='type']">

        <xsl:if test="@provides = 'frame' or @provides = 'sasl-frame'">
          <xsl:variable name="classname"><xsl:call-template name="dashToCamel"><xsl:with-param name="input" select="@name"/></xsl:call-template>Frame</xsl:variable>

          <xsl:call-template name="typeClass">
              <xsl:with-param name="license" select="$license"/>
              <xsl:with-param name="classname" select="$classname"/>
          </xsl:call-template>
        </xsl:if>

        <xsl:if test="@provides = 'delivery-state, outcome' or @provides = 'delivery-state' or @provides = 'source' or @provides = 'target' or @name = 'declare' or @name = 'discharge' or @name = 'error' or @provides = 'lifetime-policy'">
          <xsl:variable name="classname"><xsl:call-template name="dashToCamel"><xsl:with-param name="input" select="@name"/></xsl:call-template></xsl:variable>

          <xsl:call-template name="typeClass">
              <xsl:with-param name="license" select="$license"/>
              <xsl:with-param name="classname" select="$classname"/>
          </xsl:call-template>
        </xsl:if>
    </xsl:for-each>
</xsl:template>


<!-- *************************************************************************************************************** -->

<xsl:template name="typeClass">
    <xsl:param name="license"/>
    <xsl:param name="classname"/>
  <exsl:document href="{$classname}.java" method="text">
  <xsl:value-of select="$license"/>
package org.apache.qpid.jms.test.testpeer.describedtypes;

import org.apache.qpid.jms.test.testpeer.ListDescribedType;<xsl:if test="@name = 'declare' or @name = 'discharge' or @provides = 'delivery-state, outcome'">
import org.apache.qpid.proton.amqp.DescribedType;</xsl:if>
import org.apache.qpid.proton.amqp.Symbol;
import org.apache.qpid.proton.amqp.UnsignedLong;

/**
 * Generated by generate-described-types.xsl, which resides in this package.
 */
public class <xsl:value-of select="$classname"/> extends ListDescribedType
{
    public static final Symbol DESCRIPTOR_SYMBOL = Symbol.valueOf("<xsl:value-of select="descendant::node()[name()='descriptor']/@name"/>");
    public static final UnsignedLong DESCRIPTOR_CODE = UnsignedLong.valueOf(<xsl:value-of select="concat(substring(descendant::node()[name()='descriptor']/@code,1,10),substring(descendant::node()[name()='descriptor']/@code,14))"/>L);

<xsl:for-each select="descendant::node()[name()='field']">
    private static final int FIELD_<xsl:call-template name="toUpperDashToUnderscore"><xsl:with-param name="input" select="@name"/></xsl:call-template> = <xsl:value-of select="count(preceding-sibling::node()[name()='field'])"/>;</xsl:for-each>

    public <xsl:value-of select="$classname"/>(Object... fields)
    {
        super(<xsl:value-of select="count(descendant::node()[name()='field'])"/>);
        int i = 0;
        for(Object field : fields)
        {
            getFields()[i++] = field;
        }
    }

    @Override
    public Symbol getDescriptor()
    {
        return DESCRIPTOR_SYMBOL;
    }
<xsl:for-each select="descendant::node()[name()='field']">
    public <xsl:value-of select="$classname"/> set<xsl:call-template name="dashToCamel"><xsl:with-param name="input" select="@name"/></xsl:call-template>(Object o)
    {
        getFields()[FIELD_<xsl:call-template name="toUpperDashToUnderscore"><xsl:with-param name="input" select="@name"/></xsl:call-template>] = o;
        return this;
    }
</xsl:for-each>
<xsl:if test="@name = 'declare' or @name = 'discharge' or @provides = 'delivery-state, outcome'">
    @Override
    public boolean equals(Object obj)
    {
        if(obj == this)
        {
            return true;
        }

        if(!(obj instanceof DescribedType))
        {
            return false;
        }

        DescribedType d = (DescribedType) obj;
        if(!(DESCRIPTOR_CODE.equals(d.getDescriptor()) || DESCRIPTOR_SYMBOL.equals(d.getDescriptor())))
        {
            return false;
        }

        Object described = getDescribed();
        Object described2 = d.getDescribed();
        if(described == null)
        {
            return described2 == null;
        }
        else {
            return described.equals(described2);
        }
    }

    @Override
    public int hashCode()
    {
        //This is a hack, but we aren't going to hash lots of these test objects.
        return 1;
    }
</xsl:if>
}

</exsl:document>

</xsl:template>

<!-- *************************************************************************************************************** -->

<xsl:template name="constructFromLiteral">
    <xsl:param name="type"/>
    <xsl:param name="value"/>
    <xsl:choose>
        <xsl:when test="$type = 'string'">"<xsl:value-of select="$value"/></xsl:when>
        <xsl:when test="$type = 'symbol'">Symbol.valueOf("<xsl:value-of select="$value"/>")</xsl:when>
        <xsl:when test="$type = 'ubyte'">UnsignedByte.valueOf((byte) <xsl:value-of select="$value"/>)</xsl:when>
        <xsl:when test="$type = 'ushort'">UnsignedShort.valueOf((short) <xsl:value-of select="$value"/>)</xsl:when>
        <xsl:when test="$type = 'uint'">UnsignedInteger.valueOf(<xsl:value-of select="$value"/>)</xsl:when>
        <xsl:when test="$type = 'ulong'">UnsignedLong.valueOf(<xsl:value-of select="$value"/>L)</xsl:when>
        <xsl:when test="$type = 'long'"><xsl:value-of select="$value"/>L</xsl:when>
        <xsl:when test="$type = 'short'">(short)<xsl:value-of select="$value"/></xsl:when>
        <xsl:when test="$type = 'short'">(byte)<xsl:value-of select="$value"/></xsl:when>
        <xsl:otherwise><xsl:value-of select="$value"/></xsl:otherwise>
    </xsl:choose>
</xsl:template>

<!-- *************************************************************************************************************** -->
<xsl:template name="substringAfterLast"><xsl:param name="input"/><xsl:param name="arg"/>
        <xsl:choose>
            <xsl:when test="contains($input,$arg)"><xsl:call-template name="substringAfterLast"><xsl:with-param name="input"><xsl:value-of select="substring-after($input,$arg)"/></xsl:with-param><xsl:with-param name="arg"><xsl:value-of select="$arg"/></xsl:with-param></xsl:call-template></xsl:when>
            <xsl:otherwise><xsl:value-of select="$input"/></xsl:otherwise>
        </xsl:choose>
    </xsl:template>

    <xsl:template name="initCap"><xsl:param name="input"/><xsl:value-of select="translate(substring($input,1,1),'abcdefghijklmnopqrstuvwxyz','ABCDEFGHIJKLMNOPQRSTUVWXYZ')"/><xsl:value-of select="substring($input,2)"/></xsl:template>

    <xsl:template name="initLower"><xsl:param name="input"/><xsl:value-of select="translate(substring($input,1,1),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')"/><xsl:value-of select="substring($input,2)"/></xsl:template>

    <xsl:template name="toUpper"><xsl:param name="input"/><xsl:value-of select="translate($input,'abcdefghijklmnopqrstuvwxyz','ABCDEFGHIJKLMNOPQRSTUVWXYZ')"/></xsl:template>

    <xsl:template name="toUpperDashToUnderscore"><xsl:param name="input"/><xsl:value-of select="translate($input,'abcdefghijklmnopqrstuvwxyz-','ABCDEFGHIJKLMNOPQRSTUVWXYZ_')"/></xsl:template>

    <xsl:template name="dashToCamel">
        <xsl:param name="input"/>
        <xsl:choose>
            <xsl:when test="contains($input,'-')"><xsl:call-template name="initCap"><xsl:with-param name="input" select="substring-before($input,'-')"/></xsl:call-template><xsl:call-template name="dashToCamel"><xsl:with-param name="input" select="substring-after($input,'-')"/></xsl:call-template></xsl:when>
            <xsl:otherwise><xsl:call-template name="initCap"><xsl:with-param name="input" select="$input"/></xsl:call-template></xsl:otherwise>
        </xsl:choose>
    </xsl:template>

    <xsl:template name="dashToLowerCamel">
        <xsl:param name="input"/>
        <xsl:call-template name="initLower"><xsl:with-param name="input"><xsl:call-template name="dashToCamel"><xsl:with-param name="input" select="$input"/></xsl:call-template></xsl:with-param></xsl:call-template>
    </xsl:template>
</xsl:stylesheet>
