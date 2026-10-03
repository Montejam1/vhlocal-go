# stub line 1
# stub line 2
# stub line 3
# stub line 4
# stub line 5
# stub line 6
# stub line 7
# stub line 8
# stub line 9
# stub line 10
# stub line 11
# stub line 12
# stub line 13
# stub line 14
# stub line 15
# stub line 16
# stub line 17
# stub line 18
# stub line 19
# stub line 20
# stub line 21
# stub line 22
# stub line 23
# stub line 24
# stub line 25
# stub line 26
# stub line 27
# stub line 28
# stub line 29
# stub line 30
# stub line 31
# stub line 32

class UserRole(str, enum.Enum):
    ops_admin = "ops_admin"
    dispatcher = "dispatcher"
    field_worker = "field_worker"
    customer = "customer"
# stub line 39
# stub line 40
# stub line 41
# stub line 42
# stub line 43
# stub line 44
# stub line 45
# stub line 46
# stub line 47
# stub line 48
# stub line 49
# stub line 50
# stub line 51
# stub line 52
# stub line 53
# stub line 54
# stub line 55
# stub line 56
# stub line 57
# stub line 58
# stub line 59
# stub line 60
# stub line 61
# stub line 62
# stub line 63
# stub line 64
# stub line 65
# stub line 66
# stub line 67
# stub line 68
# stub line 69
# stub line 70
# stub line 71
# stub line 72
# stub line 73
# stub line 74
# stub line 75
# stub line 76
# stub line 77
# stub line 78
# stub line 79
# stub line 80
# stub line 81
# stub line 82
# stub line 83
# stub line 84
# stub line 85
# stub line 86
# stub line 87
# stub line 88
# stub line 89
# stub line 90
# stub line 91
# stub line 92
# stub line 93
# stub line 94
# stub line 95
# stub line 96
# stub line 97
# stub line 98
# stub line 99
# stub line 100
# stub line 101
# stub line 102
# stub line 103
# stub line 104
# stub line 105
# stub line 106
# stub line 107
# stub line 108
# stub line 109
# stub line 110
# stub line 111
# stub line 112
# stub line 113
# stub line 114
# stub line 115
# stub line 116
# stub line 117
# stub line 118
# stub line 119
# stub line 120
# stub line 121
class ServiceType(Base):
    __tablename__ = "service_types"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    code: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    requires_proof: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
# stub line 128
# stub line 129
# stub line 130
# stub line 131
# stub line 132
# stub line 133
# stub line 134
# stub line 135
# stub line 136
# stub line 137
# stub line 138
# stub line 139
# stub line 140
# stub line 141
# stub line 142
# stub line 143
# stub line 144
# stub line 145
# stub line 146
# stub line 147
# stub line 148
# stub line 149
# stub line 150
# stub line 151
# stub line 152
# stub line 153
# stub line 154
# stub line 155
# stub line 156
# stub line 157
# stub line 158
# stub line 159
# stub line 160
# stub line 161
# stub line 162
# stub line 163
# stub line 164
# stub line 165
# stub line 166
# stub line 167
# stub line 168
# stub line 169
# stub line 170
# stub line 171
# stub line 172
# stub line 173
# stub line 174
# stub line 175
# stub line 176
# stub line 177
# stub line 178
# stub line 179
# stub line 180
# stub line 181
# stub line 182
# stub line 183
# stub line 184
# stub line 185
# stub line 186
# stub line 187
    region = relationship("Region")


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    code: Mapped[str] = mapped_column(String(40), unique=True, nullable=False, index=True)
    customer_id: Mapped[str] = mapped_column(String(36), ForeignKey("customers.id"), nullable=False, index=True)
    location_id: Mapped[str] = mapped_column(String(36), ForeignKey("service_locations.id"), nullable=False, index=True)
    region_id: Mapped[str] = mapped_column(String(36), ForeignKey("regions.id"), nullable=False, index=True)
    service_type_id: Mapped[str] = mapped_column(String(36), ForeignKey("service_types.id"), nullable=False, index=True)
    assigned_worker_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("workers.id"), index=True)
# stub line 200
# stub line 201
# stub line 202
# stub line 203
# stub line 204
# stub line 205
# stub line 206
# stub line 207
# stub line 208
# stub line 209
# stub line 210
# stub line 211
# stub line 212
# stub line 213
# stub line 214
# stub line 215
# stub line 216
# stub line 217
# stub line 218
# stub line 219
# stub line 220
# stub line 221
# stub line 222
# stub line 223
# stub line 224
# stub line 225
# stub line 226
# stub line 227
# stub line 228
# stub line 229
# stub line 230
# stub line 231
# stub line 232
# stub line 233
# stub line 234
# stub line 235
# stub line 236
# stub line 237
# stub line 238
# stub line 239
class RouteStop(Base):
    __tablename__ = "route_stops"
    __table_args__ = (UniqueConstraint("route_id", "position", name="uq_route_position"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    route_id: Mapped[str] = mapped_column(String(36), ForeignKey("routes.id", ondelete="CASCADE"), nullable=False, index=True)
# stub line 245
# stub line 246
# stub line 247
# stub line 248
# stub line 249
# stub line 250
# stub line 251
# stub line 252
# stub line 253
# stub line 254
# stub line 255
# stub line 256
# stub line 257
# stub line 258
# stub line 259
# stub line 260
# stub line 261
# stub line 262
# stub line 263
# stub line 264
# stub line 265
# stub line 266
# stub line 267
# stub line 268
# stub line 269
# stub line 270
# stub line 271
# stub line 272
# stub line 273
# stub line 274
# stub line 275
# stub line 276
# stub line 277
# stub line 278
# stub line 279
# stub line 280
# stub line 281
# stub line 282
# stub line 283
# stub line 284
# stub line 285
# stub line 286
# stub line 287
# stub line 288
# stub line 289
# stub line 290
# stub line 291
# stub line 292
# stub line 293
# stub line 294
# stub line 295
# stub line 296
# stub line 297
# stub line 298
# stub line 299
# stub line 300
# stub line 301
# stub line 302
# stub line 303
# stub line 304
# stub line 305
# stub line 306
# stub line 307
# stub line 308
# stub line 309
# stub line 310
# stub line 311
# stub line 312
# stub line 313
# stub line 314
# stub line 315
# stub line 316
# stub line 317
# stub line 318
# stub line 319
# stub line 320
# stub line 321
# stub line 322
# stub line 323
# stub line 324
# stub line 325
# stub line 326
# stub line 327
# stub line 328
# stub line 329
# stub line 330
# stub line 331
# stub line 332
# stub line 333
# stub line 334
# stub line 335
# stub line 336
# stub line 337
# stub line 338
# stub line 339
# stub line 340
# stub line 341
# stub line 342
# stub line 343
# stub line 344
# stub line 345
# stub line 346
# stub line 347
# stub line 348
# stub line 349
# stub line 350
# stub line 351
# stub line 352
# stub line 353
# stub line 354
# stub line 355
# stub line 356
# stub line 357
# stub line 358
# stub line 359
# stub line 360
# stub line 361
# stub line 362
# stub line 363
# stub line 364
# Valid status transitions for jobs
JOB_STATUS_TRANSITIONS = {
    JobStatus.unassigned: {JobStatus.assigned, JobStatus.cancelled},
    JobStatus.assigned: {JobStatus.en_route, JobStatus.cancelled, JobStatus.unassigned, JobStatus.failed},
    JobStatus.en_route: {JobStatus.arrived, JobStatus.cancelled, JobStatus.failed},
    JobStatus.arrived: {JobStatus.in_progress, JobStatus.failed},
    JobStatus.in_progress: {JobStatus.completed, JobStatus.failed},
    JobStatus.completed: set(),
    JobStatus.cancelled: set(),
    JobStatus.failed: {JobStatus.assigned},  # allow retry
}
