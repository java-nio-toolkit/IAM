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

package com.github.reganjohn.iam.test.restaction.health;

import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.reganjohn.iam.internal.requests.restactions.HealthRetrieveActionImpl;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import com.reganjohn.c4j.api.JCA;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.mockito.Mockito.when;

public class HealthRetrieveActionTest extends RestActionTest
{
    private void withStatus(JCA.Status status)
    {
        withJCA();
        when(api.getJCA().getStatus()).thenReturn(status);
    }

    @Test
    void testReady()
    {
        withStatus(JCA.Status.READY);

        assertThatRequestTo(new HealthRetrieveActionImpl(api))
                .hasStatus(StatusReason.NO_CONTENT.code)
                .hasNoBody()
                .whenHandled();
    }

    @EnumSource(value = JCA.Status.class, mode = EnumSource.Mode.EXCLUDE, names = "READY")
    @ParameterizedTest
    void testNotReady(JCA.Status status)
    {
        withStatus(status);

        assertThatRequestTo(new HealthRetrieveActionImpl(api))
                .hasStatus(StatusReason.SERVICE_UNAVAILABLE.code)
                .hasNoBody()
                .whenHandled();
    }
}
