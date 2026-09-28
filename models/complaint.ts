/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import {
  Model,
  type InferAttributes,
  type InferCreationAttributes,
  DataTypes,
  type CreationOptional,
  type Sequelize
} from 'sequelize'

/** Kept in sync with the maximum message length enforced by the complaint form in the frontend. */
const MAX_MESSAGE_LENGTH = 4096

class Complaint extends Model<
InferAttributes<Complaint>,
InferCreationAttributes<Complaint>
> {
  declare UserId: number
  declare id: CreationOptional<number>
  declare message: string
  declare file: CreationOptional<string>
}

const ComplaintModelInit = (sequelize: Sequelize) => {
  Complaint.init(
    {
      UserId: {
        type: DataTypes.INTEGER
      },
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      message: {
        type: DataTypes.STRING(MAX_MESSAGE_LENGTH),
        // SQLite does not enforce the declared VARCHAR length, so the limit is validated explicitly
        validate: {
          len: [0, MAX_MESSAGE_LENGTH]
        }
      },
      file: DataTypes.STRING
    },
    {
      tableName: 'Complaints',
      sequelize
    }
  )
}

export { Complaint as ComplaintModel, ComplaintModelInit }
