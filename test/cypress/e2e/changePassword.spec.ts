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

    it('should not be able to change password without the current password', () => {
      cy.request({
        method: 'GET',
        url: '/rest/user/change-password?new=GonorrheaCantSeeUs!&repeat=GonorrheaCantSeeUs!',
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` },
        failOnStatusCode: false
      }).then((response) => {
        expect(response.status).to.not.equal(200)
      })
    })
  })
})
