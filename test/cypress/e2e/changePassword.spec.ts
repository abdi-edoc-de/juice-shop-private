describe('/#/privacy-security/change-password', () => {
  describe('as Morty', () => {
    beforeEach(() => {
      cy.login({
        email: 'morty',
        password: 'focusOnScienceMorty!focusOnScience'
      })
      cy.visit('/#/privacy-security/change-password')
    })

    it('should be able to change password', () => {
      cy.get('#currentPassword').focus().type('focusOnScienceMorty!focusOnScience')
      cy.get('#newPassword').focus().type('GonorrheaCantSeeUs!')
      cy.get('#newPasswordRepeat').focus().type('GonorrheaCantSeeUs!')
      cy.get('#changeButton').click()

      cy.get('.confirmation').should('not.be.hidden')
    })
  })

  describe('challenge "changePasswordBenderChallenge"', () => {
    it('should be able to change password for Bender with correct current password', () => {
      cy.login({
        email: 'bender',
        password: 'OhG0dPlease1nsertLiquor!'
      })
      cy.visit('/#/privacy-security/change-password')

      cy.get('#currentPassword').focus().type('OhG0dPlease1nsertLiquor!')
      cy.get('#newPassword').focus().type('slurmCl4ssic')
      cy.get('#newPasswordRepeat').focus().type('slurmCl4ssic')
      cy.get('#changeButton').click()

      cy.get('.confirmation').should('not.be.hidden')

      cy.login({ email: 'bender', password: 'slurmCl4ssic' })
      cy.url().should('match', /\/search/)

      cy.expectChallengeSolved({ challenge: "Change Bender's Password" })
    })
  })
})
