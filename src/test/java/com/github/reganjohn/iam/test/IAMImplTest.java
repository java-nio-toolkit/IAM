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

import com.github.adamorgan.jnt.api.socket.SocketManager;
import com.github.adamorgan.jnt.api.utils.SignType;
import com.github.reganjohn.iam.internal.managers.GlobalAccessManagerImpl;
import com.reganjohn.c4j.api.JCA;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class IAMImplTest extends IntegrationTest
{
    @Test
    void testShutdown() throws InterruptedException
    {
        GlobalAccessManagerImpl manager = mock(GlobalAccessManagerImpl.class);
        SocketManager socketManager = mock(SocketManager.class);
        JCA jca = mock(JCA.class);
        when(api.getAccessManager()).thenReturn(manager);
        when(api.getSocketManager()).thenReturn(socketManager);
        when(api.getJCA()).thenReturn(jca);
        doCallRealMethod().when(api).shutdown();

        api.shutdown();

        InOrder order = inOrder(jnt, manager, socketManager, jca);
        order.verify(jnt).shutdown();
        order.verify(jnt).awaitShutdown(30, TimeUnit.SECONDS);
        order.verify(manager).shutdown();
        order.verify(socketManager).shutdown();
        order.verify(jca).shutdown();
    }

    @Test
    void testShutdownInterrupted() throws InterruptedException
    {
        GlobalAccessManagerImpl manager = mock(GlobalAccessManagerImpl.class);
        SocketManager socketManager = mock(SocketManager.class);
        JCA jca = mock(JCA.class);
        when(api.getAccessManager()).thenReturn(manager);
        when(api.getSocketManager()).thenReturn(socketManager);
        when(api.getJCA()).thenReturn(jca);
        when(jnt.awaitShutdown(30, TimeUnit.SECONDS)).thenThrow(new InterruptedException());
        doCallRealMethod().when(api).shutdown();

        api.shutdown();

        assertThat(Thread.interrupted()).isTrue();
        InOrder order = inOrder(manager, socketManager, jca);
        order.verify(manager).shutdown();
        order.verify(socketManager).shutdown();
        order.verify(jca).shutdown();
    }

    @Test
    void testShutdownAccessManager()
    {
        GlobalAccessManagerImpl manager = new GlobalAccessManagerImpl(api, SignType.ED25519, 2, 15, TimeUnit.DAYS, "https://localhost.com");

        manager.shutdown();

        assertThatIllegalStateException().isThrownBy(() -> manager.enqueue(0));
    }
}
