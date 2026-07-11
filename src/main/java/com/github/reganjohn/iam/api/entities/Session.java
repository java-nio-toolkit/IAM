/*
 * Copyright 2026 Ada Morgan, John Regan and the IAM contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.reganjohn.iam.api.entities;

import com.github.adamorgan.jnt.api.entities.IUnique;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.internal.utils.Checks;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Collection;
import java.util.EnumSet;
import java.util.UUID;

public interface Session extends IUnique
{
    @Nonnull
    UUID getUserId();

    @Nonnull
    AccessEntryData getAccessEntry();

    @Nonnull
    default EnumSet<SessionFlag> getFlags()
    {
        return SessionFlag.getFlags(getFlagsRaw());
    }

    int getFlagsRaw();

    @Nonnull
    String getThumbprint();

    @Nullable
    String getUserAgent();

    /**
     * Represents the bit offsets used for session flags.
     */
    enum SessionFlag
    {
        UNKNOWN(-1, "Unknown", false);

        /**
         * Empty array of SessionFlag enum, useful for optimized use in {@link java.util.Collection#toArray(Object[])}.
         */
        public static final SessionFlag[] EMPTY_FLAGS = new SessionFlag[0];

        public static final int ALL = 1 | getRaw(EnumSet.allOf(SessionFlag.class));

        public static final int SYSTEM = ALL & ~getRaw();

        private final int offset;
        private final int raw;
        private final String name;
        private final boolean managed;

        SessionFlag(int offset, @Nonnull String name)
        {
            this(offset, name, true);
        }

        SessionFlag(int offset, @Nonnull String name, boolean managed)
        {
            this.offset = offset;
            this.raw = 1 << offset;
            this.name = name;
            this.managed = managed;
        }

        /**
         * The readable name as used in client.
         *
         * @return The readable name of this {@link SessionFlag SessionFlag}.
         */
        @Nonnull
        public String getName()
        {
            return this.name;
        }

        /**
         * Whether this {@link User.UserFlag UserFlag} is managed.
         *
         * @return True, if this {@link User.UserFlag UserFlag} is managed.
         */
        public boolean isManaged()
        {
            return managed;
        }

        /**
         * The binary offset of the flag.
         *
         * @return The offset that represents this {@link SessionFlag SessionFlag}.
         */
        public int getOffset()
        {
            return offset;
        }

        /**
         * The value of this flag when viewed as raw value.
         * <br>This is equivalent to: <code>1 {@literal <<} {@link #getOffset()}</code>
         *
         * @return The raw value of this specific flag.
         */
        public int getRawValue()
        {
            return raw;
        }

        /**
         * Gets the first SessionFlag relating to the provided offset.
         * <br>If there is no SessionFlag that matches the provided offset,
         * {@link #UNKNOWN} is returned.
         *
         * @param  offset
         *         The offset to match a SessionFlag to.
         *
         * @return SessionFlag relating to the provided offset.
         */
        @Nonnull
        public static SessionFlag getFromOffset(int offset)
        {
            for (SessionFlag flag : values())
            {
                if (flag.offset == offset)
                {
                    return flag;
                }
            }
            return UNKNOWN;
        }

        /**
         * A set of all SessionFlags that are specified by this raw int representation of
         * flags.
         *
         * @param  flags
         *         The raw {@code int} representation if flags.
         *
         * @return Possibly-empty EnumSet of SessionFlags.
         */
        @Nonnull
        public static EnumSet<SessionFlag> getFlags(int flags)
        {
            EnumSet<SessionFlag> foundFlags = EnumSet.noneOf(SessionFlag.class);
            if (flags == 0)
            {
                return foundFlags; // empty
            }
            for (SessionFlag flag : values())
            {
                if (flag != UNKNOWN && (flags & flag.raw) == flag.raw)
                {
                    foundFlags.add(flag);
                }
            }

            return foundFlags;
        }

        /**
         * This is effectively the opposite of {@link #getFlags(int)}, this takes 1 or more SessionFlags
         * and returns the bitmask representation of the flags.
         *
         * @param  flags
         *         The array of flags of which to form into the raw int representation.
         *
         * @throws java.lang.IllegalArgumentException
         *         When the provided SessionFlags are null.
         *
         * @return bitmask representing the provided flags.
         */
        public static int getRaw(@Nonnull SessionFlag... flags)
        {
            Checks.noneNull(flags, "SessionFlags");
            int raw = 0;
            for (SessionFlag flag : flags)
            {
                if (flag != null && flag != UNKNOWN)
                {
                    raw |= flag.raw;
                }
            }

            return raw;
        }

        /**
         * This is effectively the opposite of {@link #getFlags(int)}. This takes a collection of SessionFlags
         * and returns the bitmask representation of the flags.
         *
         * @param  flags
         *         The flags to convert
         *
         * @throws java.lang.IllegalArgumentException
         *         When the provided SessionFlags are null.
         *
         * @return bitmask representing the provided flags.
         */
        public static int getRaw(@Nonnull Collection<SessionFlag> flags)
        {
            Checks.notNull(flags, "Flag Collection");
            return getRaw(flags.toArray(EMPTY_FLAGS));
        }
    }
}
