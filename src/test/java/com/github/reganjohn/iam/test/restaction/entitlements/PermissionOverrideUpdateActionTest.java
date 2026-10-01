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

package com.github.reganjohn.iam.test.restaction.entitlements;

import com.github.adamorgan.jnt.api.exceptions.InvalidTokenException;
import com.github.adamorgan.jnt.api.exceptions.ProofAccessException;
import com.github.adamorgan.jnt.api.managers.AccessEntryManager;
import com.github.adamorgan.jnt.api.requests.StatusReason;
import com.github.adamorgan.jnt.api.utils.data.DataArray;
import com.github.adamorgan.jnt.api.utils.data.DataObject;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextData;
import com.github.adamorgan.jnt.api.utils.jose.AccessContextType;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryArray;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.api.utils.jose.AccessObjectData;
import com.github.adamorgan.jnt.api.utils.jose.ProofObjectData;
import com.github.adamorgan.jnt.internal.entities.AbstractEntityBuilder;
import com.github.adamorgan.jnt.internal.managers.AccessEntryManagerImpl;
import com.github.adamorgan.jnt.internal.managers.ProofObjectManagerImpl;
import com.github.adamorgan.jnt.internal.utils.IOUtil;
import com.github.reganjohn.iam.api.Permission;
import com.github.reganjohn.iam.api.entities.EntityBuilder;
import com.github.reganjohn.iam.api.entities.PermissionOverride;
import com.github.reganjohn.iam.api.entities.User;
import com.github.reganjohn.iam.api.exceptions.ErrorResponse;
import com.github.reganjohn.iam.api.exceptions.ErrorResponseException;
import com.github.reganjohn.iam.internal.managers.GlobalAccessManagerImpl;
import com.github.reganjohn.iam.internal.utils.PermissionUtil;
import com.github.reganjohn.iam.internal.requests.restactions.entitlements.PermissionOverrideUpdateActionImpl;
import com.github.reganjohn.iam.test.assertions.restaction.RestActionAssertions;
import com.github.reganjohn.iam.test.restaction.RestActionTest;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.UUID;
import java.util.stream.Stream;

import static com.github.adamorgan.jnt.api.managers.ProofObjectManager.JKT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class PermissionOverrideUpdateActionTest extends RestActionTest
{
    private static final UUID USER_ID = UUID.fromString("01a0f15f-ef22-7d1e-9a96-432acf9b644f");
    private static final UUID OWNER_ID = UUID.fromString("02b1a26a-f033-7e2f-8ba7-543bd0ac755a");
    private static final UUID ACTOR_ID = UUID.fromString("03c2b37b-0144-7f30-9cb8-654ce1bd866b");
    private static final UUID APPLICATION_ID = UUID.fromString("04d3c48c-1255-7041-8dc9-765df2ce977c");
    private static final String TOKEN = "access.token.value";
    private static final String THUMBPRINT = "owner-thumbprint";

    private String issuedSubject;
    private UUID issuedActor;
    private DataArray issuedPermissions;

    private PermissionOverrideUpdateActionImpl newAction()
    {
        return new PermissionOverrideUpdateActionImpl(api);
    }

    private static String hashOf(String token)
    {
        try
        {
            return IOUtil.encodeURL(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException exception)
        {
            throw new IllegalStateException(exception);
        }
    }

    private void withAccessProof(String thumbprint, String tokenHash)
    {
        AccessContextData contextData = mock(AccessContextData.class);
        when(contextData.digest()).thenReturn(thumbprint);
        ProofObjectData proof = mock(ProofObjectData.class);
        when(proof.getContext(AccessContextType.SHA_256)).thenReturn(contextData);
        when(proof.getAccessTokenHash()).thenReturn(tokenHash);
        channel.attr(ProofObjectManagerImpl.CONTEXT).set(proof);
    }

    private void withManager(boolean hasAccess)
    {
        InteractionCallbackAction<Boolean> access = completed(hasAccess);
        GlobalAccessManagerImpl manager = mock(GlobalAccessManagerImpl.class);
        when(manager.hasAccess(any())).thenReturn(access);
        when(manager.getCurrentOrder()).thenReturn(mock(AccessEntryManagerImpl.AccessEntrySnapshot.class));
        channel.attr(GlobalAccessManagerImpl.IDENTIFIER).set(manager);
    }

    private static AccessObjectData accessObject(String subject, DataObject confirmation, DataObject actor)
    {
        AccessObjectData access = mock(AccessObjectData.class);
        when(access.getThumbprint()).thenReturn("proof-thumbprint");
        when(access.getSubject()).thenReturn(subject);
        when(access.getContextData()).thenReturn(confirmation);
        when(access.getActor()).thenReturn(actor);
        return access;
    }

    private static AccessObjectData accessObject()
    {
        return accessObject(USER_ID.toString(), DataObject.empty().put(JKT, THUMBPRINT), DataObject.empty().put("sub", ACTOR_ID.toString()));
    }

    private static AccessEntryData entryOf(String thumbprint)
    {
        AccessContextData contextData = mock(AccessContextData.class);
        when(contextData.digest()).thenReturn(thumbprint);
        AccessEntryData entry = mock(AccessEntryData.class);
        when(entry.getContext(AccessContextType.SHA_256)).thenReturn(contextData);
        return entry;
    }

    private void withStoredEntitlement()
    {
        PermissionOverride entitlement = withEntitlement(USER_ID, APPLICATION_ID, OWNER_ID, 1, 0);
        User user = withUser(USER_ID, "alice", null, 0);
        withEntitlement(user, APPLICATION_ID, completed(entitlement));
        withAccessEntries(user, completed(new AccessEntryArray(Collections.singletonList(entryOf(THUMBPRINT)))));
        withRetrieval(USER_ID, completed(user));
    }

    private RestActionAssertions assertThatUpdating()
    {
        return assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString())
                .withHeader("Authorization", "DPoP " + TOKEN);
    }

    private void whenHandled(RestActionAssertions assertions, AccessObjectData access)
    {
        try (MockedStatic<AbstractEntityBuilder> parsed = mockStatic(AbstractEntityBuilder.class);
             MockedStatic<EntityBuilder> issued = mockStatic(EntityBuilder.class))
        {
            AccessObjectData issuedObject = mock(AccessObjectData.class);
            when(issuedObject.getRaw()).thenReturn(ISSUED_OBJECT);
            parsed.when(() -> AbstractEntityBuilder.createAccessObject(anyString())).thenReturn(access);
            issued.when(() -> EntityBuilder.createObjectData(anyString(), anyString(), anyString(), any(UUID.class),
                            any(DataArray.class), any(AccessEntryManager.class), any(AccessContextData.class), anyString(),
                            any(AccessEntryManagerImpl.AccessEntrySnapshot.class)))
                    .thenAnswer(invocation ->
                    {
                        issuedSubject = invocation.getArgument(2);
                        issuedActor = invocation.getArgument(3);
                        issuedPermissions = invocation.getArgument(4);
                        return issuedObject;
                    });

            assertions.whenHandled();

        }
    }

    static Stream<Arguments> testInvalidInputs()
    {
        return Stream.of(
                arguments("empty", ""),
                arguments("not_uuid", "not-a-uuid"),
                arguments("too_short", "04d3c48c-1255-7041-8dc9"),
                arguments("bad_characters", "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"),
                arguments("without_dashes", "04d3c48c125570418dc9765df2ce977c"));
    }

    static Stream<Arguments> testInvalidToken()
    {
        return Stream.of(
                arguments("no_confirmation", null, DataObject.empty().put("sub", ACTOR_ID.toString())),
                arguments("no_thumbprint_claim", DataObject.empty(), DataObject.empty().put("sub", ACTOR_ID.toString())),
                arguments("thumbprint_claim_not_string", DataObject.empty().put(JKT, 5), DataObject.empty().put("sub", ACTOR_ID.toString())),
                arguments("other_user_thumbprint", DataObject.empty().put(JKT, "another-thumbprint"), DataObject.empty().put("sub", ACTOR_ID.toString())),
                arguments("actor_without_subject", DataObject.empty().put(JKT, THUMBPRINT), DataObject.empty()),
                arguments("actor_subject_not_string", DataObject.empty().put(JKT, THUMBPRINT), DataObject.empty().put("sub", 5)),
                arguments("actor_subject_not_uuid", DataObject.empty().put(JKT, THUMBPRINT), DataObject.empty().put("sub", "application")));
    }

    @MethodSource("testInvalidInputs")
    @ParameterizedTest
    void testInvalidApplicationId(String name, String applicationId)
    {
        assertThatRequestTo(newAction())
                .withRouteParams(applicationId)
                .withHeader("Authorization", "DPoP " + TOKEN)
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(name)
                .hasNoResponse()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testValidEntitlement()
    {
        withAccessProof("proof-thumbprint", hashOf(TOKEN));
        withManager(true);
        withStoredEntitlement();

        whenHandled(assertThatUpdating()
                .hasStatus(StatusReason.OK.code)
                .hasContentType(PermissionOverrideUpdateActionImpl.MEDIA_TYPE_ACCESS)
                .hasBodyEqualTo(ISSUED_OBJECT), accessObject());

        assertThat(issuedSubject).isEqualTo(USER_ID.toString());
        assertThat(issuedActor).isEqualTo(ACTOR_ID);
        assertThat(issuedPermissions.toString()).isEqualTo(PermissionUtil.toDataArray(Permission.getPermissions(1)).toString());
    }

    @ValueSource(strings = {"", "DPoP", "DPoP first second"})
    @ParameterizedTest
    void testMalformedAuthorization(String authorization)
    {
        withAccessProof("proof-thumbprint", hashOf(TOKEN));

        assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString())
                .withHeader("Authorization", authorization)
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testMissingAuthorization()
    {
        withAccessProof("proof-thumbprint", hashOf(TOKEN));

        assertThatRequestTo(newAction())
                .withRouteParams(APPLICATION_ID.toString())
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot()
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testMissingProof()
    {
        assertThatUpdating()
                .hasNoResponse()
                .hasFailureOfType(ProofAccessException.class)
                .whenHandled();

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testProofOfAnotherKey()
    {
        withAccessProof("another-thumbprint", hashOf(TOKEN));

        whenHandled(assertThatUpdating()
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class), accessObject());

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testProofOfAnotherToken()
    {
        withAccessProof("proof-thumbprint", hashOf("another.token"));

        whenHandled(assertThatUpdating()
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class), accessObject());

        verify(api, never()).retrieveUserById(any());
    }

    @Test
    void testUserToken()
    {
        withAccessProof("proof-thumbprint", hashOf(TOKEN));
        withManager(true);
        withStoredEntitlement();
        AccessObjectData access = accessObject(USER_ID.toString(), DataObject.empty().put(JKT, THUMBPRINT), null);

        whenHandled(assertThatUpdating()
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(), access);
    }

    @MethodSource
    @ParameterizedTest
    void testInvalidToken(String name, DataObject confirmation, DataObject actor)
    {
        withAccessProof("proof-thumbprint", hashOf(TOKEN));
        withManager(true);
        withStoredEntitlement();
        AccessObjectData access = accessObject(USER_ID.toString(), confirmation, actor);

        whenHandled(assertThatUpdating()
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(name), access);
    }

    @Test
    void testDeniedAccess()
    {
        withAccessProof("proof-thumbprint", hashOf(TOKEN));
        withManager(false);
        withStoredEntitlement();

        whenHandled(assertThatUpdating()
                .hasNoResponse()
                .hasFailureOfType(InvalidTokenException.class), accessObject());
    }

    @Test
    void testUnknownUser()
    {
        withAccessProof("proof-thumbprint", hashOf(TOKEN));
        withManager(true);
        withRetrieval(USER_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_USER)));

        whenHandled(assertThatUpdating()
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(), accessObject());
    }

    @Test
    void testUnknownEntitlement()
    {
        withAccessProof("proof-thumbprint", hashOf(TOKEN));
        withManager(true);
        User user = withUser(USER_ID, "alice", null, 0);
        withEntitlement(user, APPLICATION_ID, failed(new ErrorResponseException(ErrorResponse.UNKNOWN_ENTITLEMENT)));
        withRetrieval(USER_ID, completed(user));

        whenHandled(assertThatUpdating()
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(), accessObject());
    }

    @Test
    void testUnknownKeys()
    {
        withAccessProof("proof-thumbprint", hashOf(TOKEN));
        withManager(true);
        PermissionOverride entitlement = withEntitlement(USER_ID, APPLICATION_ID, OWNER_ID, 1, 0);
        User user = withUser(USER_ID, "alice", null, 0);
        withEntitlement(user, APPLICATION_ID, completed(entitlement));
        withAccessEntries(user, failed(new ErrorResponseException(ErrorResponse.MISSING_ACCESS)));
        withRetrieval(USER_ID, completed(user));

        whenHandled(assertThatUpdating()
                .hasNoResponse()
                .hasFailureOfType(ErrorResponseException.class)
                .hasFailureMatchingSnapshot(), accessObject());
    }
}
