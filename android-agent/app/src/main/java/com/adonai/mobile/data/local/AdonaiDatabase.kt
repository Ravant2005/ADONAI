package com.adonai.mobile.data.local

import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.RoomDatabase

@Entity(tableName = "local_security_events")
data class LocalEventEntity(
    @PrimaryKey val eventId: String,
    val environment: String, // "REAL" or "LAB"
    val sourceType: String,
    val eventType: String,
    val appContext: String,
    val destination: String,
    val evidenceClass: String, // "OBSERVED", "INFERRED", "CONFIRMED"
    val summary: String,
    val syncedToMac: Boolean,
    val createdAtIso: String
)

@Entity(tableName = "trusted_contacts")
data class TrustedContactEntity(
    @PrimaryKey val recipientId: String,
    val identifier: String,
    val displayName: String,
    val trustLevel: String, // "TRUSTED", "KNOWN", "UNKNOWN"
    val overridePolicy: String = "NEVER_SUPPRESS_OTP_OR_COMPROMISE"
)

@Dao
interface AdonaiDao {
    @Query("SELECT * FROM local_security_events WHERE environment = :env ORDER BY createdAtIso DESC")
    suspend fun getEventsByEnvironment(env: String): List<LocalEventEntity>

    @Query("SELECT * FROM local_security_events WHERE syncedToMac = 0")
    suspend fun getUnsyncedEvents(): List<LocalEventEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertEvent(event: LocalEventEntity)

    @Query("DELETE FROM local_security_events WHERE environment = :env")
    suspend fun purgeEventsByEnvironment(env: String)
}

@Database(entities = [LocalEventEntity::class, TrustedContactEntity::class], version = 1, exportSchema = false)
abstract class AdonaiDatabase : RoomDatabase() {
    abstract fun adonaiDao(): AdonaiDao
}
