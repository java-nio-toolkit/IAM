/*
 * Copyright 2026 Ada Morgan, John Regan and the IAM contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.reganjohn.iam.test;

import com.github.adamorgan.jnt.internal.JNTImpl;
import com.github.adamorgan.jnt.internal.utils.config.RestConfig;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.github.reganjohn.iam.internal.requests.restactions.AbstractOverrideActionImpl;
import com.github.reganjohn.iam.test.assertions.restaction.RestActionAssertions;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInfo;
import org.mockito.Mock;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.openMocks;

public class IntegrationTest extends AbstractSnapshotTest
{
    protected static final String IAM_IDENTIFIER = "iam.test";
    protected static final String JNT_IDENTIFIER = "jnt.test";

    @Mock
    protected IAMImpl api;

    @Mock
    protected JNTImpl jnt;

    protected EmbeddedChannel channel;
    protected ChannelHandlerContext context;

    private AutoCloseable closeable;
    private int expectedHandlingCount;
    private int actualHandlingCount;

    @BeforeEach
    protected final void setup()
    {
        expectedHandlingCount = 0;
        actualHandlingCount = 0;
        closeable = openMocks(this);
        when(api.getIdentifierString()).thenReturn(IAM_IDENTIFIER);
        when(api.getJNT()).thenReturn(jnt);
        when(jnt.getIdentifierString()).thenReturn(JNT_IDENTIFIER);
        when(jnt.getRestConfig()).thenReturn(RestConfig.getDefault());

        ChannelInboundHandlerAdapter probe = new ChannelInboundHandlerAdapter();
        channel = new EmbeddedChannel(probe);
        context = channel.pipeline().context(probe);
        channel.attr(JNTImpl.IDENTIFIER).set(jnt);
    }

    @AfterEach
    protected final void teardown(TestInfo testInfo) throws Exception
    {
        try
        {
            assertThat(actualHandlingCount)
                    .as("Requests handled by " + testInfo.getDisplayName())
                    .isEqualTo(expectedHandlingCount);
        }
        finally
        {
            channel.finishAndReleaseAll();
            closeable.close();
        }
    }

    @CheckReturnValue
    protected RestActionAssertions assertThatRequestTo(@Nonnull AbstractOverrideActionImpl action)
    {
        expectedHandlingCount += 1;
        return RestActionAssertions.assertThatAction(snapshotHandler, action, channel, context, () -> actualHandlingCount += 1);
    }

    protected void assertThatNoRequestsWereHandled()
    {
        assertThat(actualHandlingCount).isZero();
    }
}
