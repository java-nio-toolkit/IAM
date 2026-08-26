package com.github.reganjohn.iam.api.interactions;

import com.github.adamorgan.jnt.api.entities.IUnique;
import com.github.adamorgan.jnt.api.utils.jose.AccessEntryData;
import com.github.adamorgan.jnt.internal.utils.Checks;
import com.github.reganjohn.iam.internal.IAMImpl;
import com.reganjohn.c4j.api.requests.objaction.InteractionCallbackAction;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import java.util.Collection;
import java.util.EnumSet;
import java.util.UUID;

public interface AccessContextInteraction extends IUnique
{
    @Nonnull
    IAMImpl getIAM();

    @Nonnull
    UUID getOwnerId();

    @Nonnull
    UUID getApplicationId();

    @Nonnull
    String getThumbprint();

    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<AccessEntryData> retrieveAccess();

    @Nonnull
    default EnumSet<AccessContextFlag> getFlags()
    {
        return AccessContextFlag.getFlags(getFlagsRaw());
    }

    long getFlagsRaw();

    @Nonnull
    @CheckReturnValue
    InteractionCallbackAction<Void> revoke();

    enum AccessContextFlag
    {
        DELETED(34, false),
        UNKNOWN(-1, false);

        /**
         * Empty array of AccessContextFlag enum, useful for optimized use in {@link java.util.Collection#toArray(Object[])}.
         */
        public static final AccessContextFlag[] EMPTY_FLAGS = new AccessContextFlag[0];

        public static final long ALL = 1 | getRaw(EnumSet.allOf(AccessContextFlag.class));

        public static final long SYSTEM = ALL & ~getRaw();

        private final long offset;
        private final long raw;
        private final boolean managed;

        AccessContextFlag(long offset, boolean managed)
        {
            this.offset = offset;
            this.raw = 1L << offset;
            this.managed = managed;
        }

        /**
         * The binary offset of the flag.
         *
         * @return The offset that represents this {@link AccessContextFlag AccessContextFlag}.
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
         * Whether this {@link AccessContextFlag AccessContextFlag} is managed.
         *
         * @return True, if this {@link AccessContextFlag AccessContextFlag} is managed.
         */
        public boolean isManaged()
        {
            return managed;
        }

        /**
         * Gets the first AccessContextFlag relating to the provided offset.
         * <br>If there is no AccessContextFlag that matches the provided offset,
         * {@link #UNKNOWN} is returned.
         *
         * @param  offset
         *         The offset to match a AccessContextFlag to.
         *
         * @return AccessContextFlag relating to the provided offset.
         */
        @Nonnull
        public static AccessContextFlag getFromOffset(int offset)
        {
            for (AccessContextFlag flag : values())
            {
                if (flag.offset == offset)
                {
                    return flag;
                }
            }
            return UNKNOWN;
        }

        /**
         * A set of all AccessContextFlags that are specified by this raw int representation of
         * flags.
         *
         * @param  flags
         *         The raw {@code int} representation if flags.
         *
         * @return Possibly-empty EnumSet of AccessContextFlags.
         */
        @Nonnull
        public static EnumSet<AccessContextFlag> getFlags(long flags)
        {
            EnumSet<AccessContextFlag> foundFlags = EnumSet.noneOf(AccessContextFlag.class);
            if (flags == 0)
            {
                return foundFlags; // empty
            }
            for (AccessContextFlag flag : values())
            {
                if (flag != UNKNOWN && (flags & flag.raw) == flag.raw)
                {
                    foundFlags.add(flag);
                }
            }

            return foundFlags;
        }

        /**
         * This is effectively the opposite of {@link #getFlags(long)}, this takes 1 or more AccessContextFlags
         * and returns the bitmask representation of the flags.
         *
         * @param  flags
         *         The array of flags of which to form into the raw int representation.
         *
         * @throws java.lang.IllegalArgumentException
         *         When the provided AccessContextFlags are null.
         *
         * @return bitmask representing the provided flags.
         */
        public static long getRaw(@Nonnull AccessContextFlag... flags)
        {
            Checks.noneNull(flags, "AccessContextFlags");
            long raw = 0;
            for (AccessContextFlag flag : flags)
            {
                if (flag != null && flag != UNKNOWN)
                {
                    raw |= flag.raw;
                }
            }

            return raw;
        }

        /**
         * This is effectively the opposite of {@link #getFlags(long)}. This takes a collection of AccessContextFlags
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
        public static long getRaw(@Nonnull Collection<AccessContextFlag> flags)
        {
            Checks.notNull(flags, "Flag Collection");
            return getRaw(flags.toArray(EMPTY_FLAGS));
        }
    }
}
