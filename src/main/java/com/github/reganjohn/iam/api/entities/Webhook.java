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

package com.github.reganjohn.iam.api.entities;

import com.github.adamorgan.jnt.api.entities.IUnique;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.reganjohn.iam.api.IAM;
import com.github.reganjohn.iam.api.Scope;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.EnumSet;
import java.util.UUID;

public interface Webhook extends IUnique
{
    /** The maximum length a name can be ({@value}) */
    int MAX_NAME_LENGTH = 80;
    /** The maximum length for any Icon CID set on an hook ({@value}) */
    int ICON_CID_MAX_LENGTH = 128;

    @Nonnull
    IAM getIAM();

    @Nonnull
    String getName();

    @Nonnull
    UUID getOwnerId();

    @Nullable
    String getAvatarId();

    @Nonnull
    String getUrl();

    @Nonnull
    OffsetDateTime getTimeUpdated();

    long getScopesRaw();

    @Nonnull
    default EnumSet<Scope> getScopes()
    {
        return Scope.getScopes(getScopesRaw());
    }

    long getFlagsRaw();

    @Nonnull
    default EnumSet<WebhookFlag> getFlags()
    {
        return WebhookFlag.getFlags(getFlagsRaw());
    }

    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<Void> delete();

    /**
     * Represents the bit offsets used for webhook flags.
     */
    enum WebhookFlag
    {
        DELETED(34, false),
        UNKNOWN(-1, false);

        /**
         * Empty array of WebhookFlag enum, useful for optimized use in {@link java.util.Collection#toArray(Object[])}.
         */
        public static final WebhookFlag[] EMPTY_FLAGS = new WebhookFlag[0];

        public static final long ALL = 1 | getRaw(EnumSet.allOf(WebhookFlag.class));

        public static final long SYSTEM = ALL & ~getRaw();

        private final long offset;
        private final long raw;
        private final boolean managed;

        WebhookFlag(long offset, boolean managed)
        {
            this.offset = offset;
            this.raw = 1L << offset;
            this.managed = managed;
        }

        /**
         * The binary offset of the flag.
         *
         * @return The offset that represents this {@link WebhookFlag WebhookFlag}.
         */
        public long getOffset()
        {
            return offset;
        }

        /**
         * The value of this flag when viewed as raw value.
         * <br>This is equivalent to: <code>1 {@literal <<} {@link #getOffset()}</code>
         *
         * @return The raw value of this specific flag.
         */
        public long getRawValue()
        {
            return raw;
        }

        /**
         * Whether this {@link WebhookFlag WebhookFlag} is managed.
         *
         * @return True, if this {@link WebhookFlag WebhookFlag} is managed.
         */
        public boolean isManaged()
        {
            return managed;
        }

        /**
         * Gets the first WebhookFlag relating to the provided offset.
         * <br>If there is no WebhookFlag that matches the provided offset,
         * {@link #UNKNOWN} is returned.
         *
         * @param  offset
         *         The offset to match a WebhookFlag to.
         *
         * @return WebhookFlag relating to the provided offset.
         */
        @Nonnull
        public static WebhookFlag getFromOffset(int offset)
        {
            for (WebhookFlag flag : values())
            {
                if (flag.offset == offset)
                {
                    return flag;
                }
            }
            return UNKNOWN;
        }

        /**
         * A set of all WebhookFlags that are specified by this raw int representation of
         * flags.
         *
         * @param  flags
         *         The raw {@code int} representation if flags.
         *
         * @return Possibly-empty EnumSet of WebhookFlags.
         */
        @Nonnull
        public static EnumSet<WebhookFlag> getFlags(long flags)
        {
            EnumSet<WebhookFlag> foundFlags = EnumSet.noneOf(WebhookFlag.class);
            if (flags == 0)
            {
                return foundFlags; // empty
            }
            for (WebhookFlag flag : values())
            {
                if (flag != UNKNOWN && (flags & flag.raw) == flag.raw)
                {
                    foundFlags.add(flag);
                }
            }

            return foundFlags;
        }

        /**
         * This is effectively the opposite of {@link #getFlags(long)}, this takes 1 or more WebhookFlags
         * and returns the bitmask representation of the flags.
         *
         * @param  flags
         *         The array of flags of which to form into the raw int representation.
         *
         * @throws java.lang.IllegalArgumentException
         *         When the provided WebhookFlags are null.
         *
         * @return bitmask representing the provided flags.
         */
        public static long getRaw(@Nonnull WebhookFlag... flags)
        {
            Checks.noneNull(flags, "WebhookFlags");
            long raw = 0;
            for (WebhookFlag flag : flags)
            {
                if (flag != null && flag != UNKNOWN)
                {
                    raw |= flag.raw;
                }
            }

            return raw;
        }

        /**
         * This is effectively the opposite of {@link #getFlags(long)}. This takes a collection of WebhookFlags
         * and returns the bitmask representation of the flags.
         *
         * @param  flags
         *         The flags to convert
         *
         * @throws java.lang.IllegalArgumentException
         *         When the provided UserFLags are null.
         *
         * @return bitmask representing the provided flags.
         */
        public static long getRaw(@Nonnull Collection<WebhookFlag> flags)
        {
            Checks.notNull(flags, "Flag Collection");
            return getRaw(flags.toArray(EMPTY_FLAGS));
        }
    }
}
