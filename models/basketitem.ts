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

class BasketItem extends Model<
InferAttributes<BasketItem>,
InferCreationAttributes<BasketItem>
> {
  declare ProductId: number
  declare BasketId: number
  declare id: CreationOptional<number>
  declare quantity: number
}

const BasketItemModelInit = (sequelize: Sequelize) => {
  BasketItem.init(
    {
      ProductId: {
        type: DataTypes.INTEGER
      },
      BasketId: {
        type: DataTypes.INTEGER
      },
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      quantity: {
        type: DataTypes.INTEGER,
        // A basket item always represents at least one ordered product. Persisting a
        // zero or negative quantity would allow negative line totals (and in turn
        // negative order totals crediting the customer's wallet) at checkout.
        validate: {
          isInt: true,
          min: 1
        }
      }
    },
    {
      tableName: 'BasketItems',
      sequelize
    }
  )
}

export { BasketItem as BasketItemModel, BasketItemModelInit }
