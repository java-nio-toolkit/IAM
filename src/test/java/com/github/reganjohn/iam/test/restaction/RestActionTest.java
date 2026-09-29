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

package com.github.reganjohn.iam.test.restaction;

import com.github.adamorgan.jnt.api.managers.AccessEntryManager;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextData;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextType;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.api.utils.jose.ProofObjectData;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ProofObjectManagerImpl;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.test.IntegrationTest;
import com.reganjohn.c4j.api.requests.Consistency;
import com.reganjohn.c4j.internal.JCAImpl;
import io.netty.util.HashedWheelTimer;
import io.netty.util.concurrent.DefaultThreadFactory;
import org.junit.jupiter.api.AfterEach;
import org.mockito.MockedStatic;

import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class RestActionTest extends IntegrationTest
{
    protected static final String THUMBPRINT = "thumbprint";
    protected static final String ISSUED_OBJECT = "issued.access.object";

    private HashedWheelTimer timer;

    protected void withProof() throws GeneralSecurityException
    {
        AccessContextData contextData = mock(AccessContextData.class);
        when(contextData.digest()).thenReturn(THUMBPRINT);

        install(newManager(SignType.ES256), contextData);
    }

    protected AccessEntryData withProof(SignType type)
    {
        AccessEntryManagerImpl manager = newManager(type);
        AccessEntryData entry = manager.getCurrentOrder();
        install(manager, entry.getContext(AccessContextType.SHA_256));
        return entry;
    }

    private AccessEntryManagerImpl newManager(SignType type)
    {
        if (timer == null)
            timer = new HashedWheelTimer(new DefaultThreadFactory("iam-test-timer", true), 1, TimeUnit.SECONDS);
        return new AccessEntryManagerImpl(timer, type, 1, 1, TimeUnit.HOURS, Collections.singletonList("iam.test"));
    }

    private void install(AccessEntryManagerImpl manager, AccessContextData contextData)
    {
        ProofObjectData proof = mock(ProofObjectData.class);
        when(proof.getContext(AccessContextType.SHA_256)).thenReturn(contextData);
        when(proof.getEntryData()).thenReturn(manager.getCurrentOrder());

        channel.attr(ProofObjectManagerImpl.CONTEXT).set(proof);
        channel.attr(AccessEntryManagerImpl.IDENTIFIER).set(manager);
    }

    @AfterEach
    void stopTimer()
    {
        if (timer != null)
            timer.stop();
        timer = null;
    }

    protected void withJca()
    {
        JCAImpl jca = mock(JCAImpl.class);
        when(jca.getConsistency()).thenReturn(Consistency.QUORUM);
        when(api.getJCA()).thenReturn(jca);
    }

    protected static void withIssuedObject(MockedStatic<EntityBuilder> builder)
    {
        AccessObjectData issued = mock(AccessObjectData.class);
        when(issued.getRaw()).thenReturn(ISSUED_OBJECT);
        builder.when(() -> EntityBuilder.createObjectData(anyString(), anyString(), anyString(),
                        any(AccessEntryManager.class), any(AccessContextData.class), anyString(),
                        any(AccessEntryManagerImpl.AccessEntrySnapshot.class)))
                .thenReturn(issued);
    }
}
