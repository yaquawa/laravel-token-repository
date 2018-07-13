<?php

namespace Yaquawa\Laravel\TokenRepository;

use Illuminate\Support\Str;
use Illuminate\Support\Carbon;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Hashing\Hasher as HasherContract;
use Yaquawa\Laravel\TokenRepository\Contracts\TokenRepository;

class DatabaseTokenRepository implements TokenRepository
{
    /**
     * The database connection instance.
     *
     * @var \Illuminate\Database\ConnectionInterface
     */
    protected $connection;

    /**
     * The Hasher implementation.
     *
     * @var \Illuminate\Contracts\Hashing\Hasher
     */
    protected $hasher;

    /**
     * The token database table.
     *
     * @var string
     */
    protected $table;

    /**
     * The hashing key.
     *
     * @var string
     */
    protected $hashKey;

    /**
     * The number of seconds a token should last.
     *
     * @var int
     */
    protected $expires;

    /**
     * The filter function called before "INSERT INTO" operation.
     * The returned value should be an array representing a row.
     *
     * @var callable
     */
    protected $payloadFilter;

    /**
     * Create a new token repository instance.
     *
     * @param  \Illuminate\Database\ConnectionInterface $connection
     * @param  \Illuminate\Contracts\Hashing\Hasher $hasher
     * @param  string $table
     * @param  string $hashKey
     * @param  int $expires
     *
     * @param callable|null $payloadFilter
     */
    public function __construct(
        ConnectionInterface $connection,
        HasherContract $hasher,
        string $table,
        string $hashKey,
        int $expires = 60,
        callable $payloadFilter = null
    ) {
        $this->table         = $table;
        $this->hasher        = $hasher;
        $this->hashKey       = $hashKey;
        $this->expires       = $expires * 60;
        $this->connection    = $connection;
        $this->payloadFilter = $payloadFilter;
    }

    /**
     * Create a new token record.
     *
     * @param  Authenticatable $user
     *
     * @return string
     */
    public function create(Authenticatable $user)
    {
        $this->deleteExisting($user);

        // We will create a new, random token for the user so that we can e-mail them
        // a safe link to the password reset form. Then we will insert a record in
        // the database so that we can verify the token within the actual reset.
        $token = $this->createNewToken();

        $this->getTable()->insert($this->getPayload($user, $token));

        return $token;
    }

    /**
     * Delete all existing reset tokens from the database.
     *
     * @param  Authenticatable $user
     *
     * @return int
     */
    protected function deleteExisting(Authenticatable $user)
    {
        return $this->getTable()->where('user_id', $user->getAuthIdentifier())->delete();
    }

    /**
     * Build the record payload for the table.
     *
     * @param  Authenticatable $user
     * @param  string $token
     *
     * @return array
     */
    protected function getPayload(Authenticatable $user, string $token)
    {
        $payLoad = ['user_id' => $user->getAuthIdentifier(), 'token' => $this->hasher->make($token), 'created_at' => new Carbon];

        if ($this->payloadFilter) {
            $payLoad = \call_user_func($this->payloadFilter, $payLoad, $user);
        }

        return $payLoad;
    }

    /**
     * Get the record by the given user's id
     * and make sure the token is not expired.
     *
     * @param Authenticatable $user
     * @param string $token
     *
     * @return array|null
     */
    public function find(Authenticatable $user, string $token)
    {
        $record = (array)$this->getTable()->where(
            'user_id', $user->getAuthIdentifier()
        )->first();

        $exists = $record &&
                  ! $this->tokenExpired($record['created_at']) &&
                  $this->hasher->check($token, $record['token']);

        return $exists ? $record : null;
    }

    /**
     * Determine if a token record exists and is valid.
     *
     * @param  Authenticatable $user
     * @param  string $token
     *
     * @return bool
     */
    public function exists(Authenticatable $user, $token): bool
    {
        return (bool)$this->find($user, $token);
    }

    /**
     * Determine if the token has expired.
     *
     * @param  string $createdAt
     *
     * @return bool
     */
    protected function tokenExpired($createdAt)
    {
        return Carbon::parse($createdAt)->addSeconds($this->expires)->isPast();
    }

    /**
     * Delete a token record by user.
     *
     * @param  \Illuminate\Contracts\Auth\CanResetPassword $user
     *
     * @return void
     */
    public function delete(Authenticatable $user)
    {
        $this->deleteExisting($user);
    }

    /**
     * Delete expired tokens.
     *
     * @return void
     */
    public function deleteExpired()
    {
        $expiredAt = Carbon::now()->subSeconds($this->expires);

        $this->getTable()->where('created_at', '<', $expiredAt)->delete();
    }

    /**
     * Create a new token for the user.
     *
     * @return string
     */
    public function createNewToken()
    {
        return hash_hmac('sha256', Str::random(40), $this->hashKey);
    }

    /**
     * Get the database connection instance.
     *
     * @return \Illuminate\Database\ConnectionInterface
     */
    public function getConnection()
    {
        return $this->connection;
    }

    /**
     * Begin a new database query against the table.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    protected function getTable()
    {
        return $this->connection->table($this->table);
    }

    /**
     * Get the hasher instance.
     *
     * @return \Illuminate\Contracts\Hashing\Hasher
     */
    public function getHasher()
    {
        return $this->hasher;
    }
}
